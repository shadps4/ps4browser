#include "game_list_frame.h"
#include "gui_settings.h"
#include "custom_table_widget_item.h"
#include "qt_utils.h"
#include "../emulator/fileFormat/PSF.h"
#include <QPainter>
#include <unordered_set>

game_list_frame::game_list_frame(std::shared_ptr<gui_settings> gui_settings, QWidget* parent)
	: custom_dock_widget(tr("Game List"), parent)
	, m_gui_settings(std::move(gui_settings))
{
	m_icon_size = gui::game_list_icon_size_min; // ensure a valid size
	m_is_list_layout = m_gui_settings->GetValue(gui::game_list_listMode).toBool();
	m_margin_factor = m_gui_settings->GetValue(gui::game_list_marginFactor).toReal();
	m_text_factor = m_gui_settings->GetValue(gui::game_list_textFactor).toReal();
	m_icon_color = m_gui_settings->GetValue(gui::game_list_iconColor).value<QColor>();
	m_col_sort_order = m_gui_settings->GetValue(gui::game_list_sortAsc).toBool() ? Qt::AscendingOrder : Qt::DescendingOrder;
	m_sort_column = m_gui_settings->GetValue(gui::game_list_sortCol).toInt();

	m_old_layout_is_list = m_is_list_layout;

	// Save factors for first setup
	m_gui_settings->SetValue(gui::game_list_iconColor, m_icon_color);
	m_gui_settings->SetValue(gui::game_list_marginFactor, m_margin_factor);
	m_gui_settings->SetValue(gui::game_list_textFactor, m_text_factor);

	m_game_dock = new QMainWindow(this);
	m_game_dock->setWindowFlags(Qt::Widget);
	setWidget(m_game_dock);

	m_game_grid = new game_list_grid(QSize(), m_icon_color, m_margin_factor, m_text_factor, false);

	m_game_list = new game_list_table();
	m_game_list->setShowGrid(false);
	m_game_list->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_game_list->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_game_list->setSelectionMode(QAbstractItemView::SingleSelection);
	m_game_list->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
	m_game_list->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	m_game_list->verticalScrollBar()->installEventFilter(this);
	m_game_list->verticalScrollBar()->setSingleStep(20);
	m_game_list->horizontalScrollBar()->setSingleStep(20);
	m_game_list->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
	m_game_list->verticalHeader()->setVisible(false);
	m_game_list->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
	m_game_list->horizontalHeader()->setHighlightSections(false);
	m_game_list->horizontalHeader()->setSortIndicatorShown(true);
	m_game_list->horizontalHeader()->setStretchLastSection(true);
	m_game_list->horizontalHeader()->setDefaultSectionSize(150);
	m_game_list->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
	m_game_list->setContextMenuPolicy(Qt::CustomContextMenu);
	m_game_list->setAlternatingRowColors(true);
	m_game_list->installEventFilter(this);
	m_game_list->setColumnCount(gui::column_count);

	m_central_widget = new QStackedWidget(this);
	m_central_widget->addWidget(m_game_list);
	m_central_widget->addWidget(m_game_grid);
	m_central_widget->setCurrentWidget(m_is_list_layout ? m_game_list : m_game_grid);

	m_game_dock->setCentralWidget(m_central_widget);

	// Actions regarding showing/hiding columns
	auto add_column = [this](gui::game_list_columns col, const QString& header_text, const QString& action_text)
	{
		m_game_list->setHorizontalHeaderItem(col, new QTableWidgetItem(header_text));
		m_columnActs.append(new QAction(action_text, this));
	};

	add_column(gui::column_icon, tr("Icon"), tr("Show Icons"));
	add_column(gui::column_name, tr("Name"), tr("Show Names"));
	add_column(gui::column_serial, tr("Serial"), tr("Show Serials"));
	add_column(gui::column_firmware, tr("Firmware"), tr("Show Firmwares"));
	add_column(gui::column_version, tr("Version"), tr("Show Versions"));
	add_column(gui::column_category, tr("Category"), tr("Show Categories"));
	add_column(gui::column_path, tr("Path"), tr("Show Paths"));

	for (int col = 0; col < m_columnActs.count(); ++col)
	{
		m_columnActs[col]->setCheckable(true);

		connect(m_columnActs[col], &QAction::triggered, this, [this, col](bool checked)
		{
			if (!checked) // be sure to have at least one column left so you can call the context menu at all time
			{
				int c = 0;
				for (int i = 0; i < m_columnActs.count(); ++i)
				{
					if (m_gui_settings->GetGamelistColVisibility(i) && ++c > 1)
						break;					
				}
				if (c < 2)
				{
					m_columnActs[col]->setChecked(true); // re-enable the checkbox if we don't change the actual state
					return;
				}
			}
			m_game_list->setColumnHidden(col, !checked); // Negate because it's a set col hidden and we have menu say show.
			m_gui_settings->SetGamelistColVisibility(col, checked);

			if (checked) // handle hidden columns that have zero width after showing them (stuck between others)
			{
				FixNarrowColumns();
			}
		});
	}

	//events
	connect(m_game_list->horizontalHeader(), &QHeaderView::customContextMenuRequested, this, [this](const QPoint& pos)
		{
			QMenu* configure = new QMenu(this);
			configure->addActions(m_columnActs);
			configure->exec(m_game_list->horizontalHeader()->viewport()->mapToGlobal(pos));
		});
	connect(m_game_list->horizontalHeader(), &QHeaderView::sectionClicked, this, &game_list_frame::OnHeaderColumnClicked);
	connect(&m_repaint_watcher, &QFutureWatcher<game_list_item*>::resultReadyAt, this, [this](int index)
	{
		if (!m_is_list_layout) return;
		if (game_list_item* item = m_repaint_watcher.resultAt(index))
		{
				item->call_icon_func();
		}
	});
	connect(&m_repaint_watcher, &QFutureWatcher<game_list_item*>::finished, this, &game_list_frame::OnRepaintFinished);

	connect(&m_refresh_watcher, &QFutureWatcher<void>::finished, this, &game_list_frame::OnRefreshFinished);
	connect(&m_refresh_watcher, &QFutureWatcher<void>::canceled, this, [this]()
	{
		gui::utils::stop_future_watcher(m_repaint_watcher, true);

		m_path_list.clear();
		m_game_data.clear();
		m_games.clear();
	});
}
game_list_frame::~game_list_frame() {
	gui::utils::stop_future_watcher(m_repaint_watcher, true);
	gui::utils::stop_future_watcher(m_refresh_watcher, true);
	SaveSettings();
}

void game_list_frame::OnRefreshFinished()
{
	gui::utils::stop_future_watcher(m_repaint_watcher, true);
	for (auto&& g : m_games)
	{
		m_game_data.push_back(g);
	}
	m_games.clear();
	// Sort by name at the very least.
	std::sort(m_game_data.begin(), m_game_data.end(), [&](const game_info& game1, const game_info& game2)
	{
		const QString title1 = m_titles.value(QString::fromStdString(game1->info.serial), QString::fromStdString(game1->info.name));
		const QString title2 = m_titles.value(QString::fromStdString(game2->info.serial), QString::fromStdString(game2->info.name));
		return title1.toLower() < title2.toLower();
	});

	m_path_list.clear();

	Refresh();
}

void game_list_frame::OnRepaintFinished()
{
	if (m_is_list_layout)
	{
		// Fixate vertical header and row height
		m_game_list->verticalHeader()->setMinimumSectionSize(m_icon_size.height());
		m_game_list->verticalHeader()->setMaximumSectionSize(m_icon_size.height());

		// Resize the icon column
		m_game_list->resizeColumnToContents(gui::column_icon);

		// Shorten the last section to remove horizontal scrollbar if possible
		m_game_list->resizeColumnToContents(gui::column_count - 1);
	}
	else
	{
		// The game grid needs to be recreated from scratch
		int games_per_row = 0;

		if (m_icon_size.width() > 0 && m_icon_size.height() > 0)
		{
			games_per_row = width() / (m_icon_size.width() + m_icon_size.width() * m_game_grid->getMarginFactor() * 2);
		}

		const int scroll_position = m_game_grid->verticalScrollBar()->value();
		//TODO add connections
		PopulateGameGrid(games_per_row, m_icon_size, m_icon_color);
		m_central_widget->addWidget(m_game_grid);
		m_central_widget->setCurrentWidget(m_game_grid);
		m_game_grid->verticalScrollBar()->setValue(scroll_position);
	}
}

bool game_list_frame::IsEntryVisible(const game_info& game)
{
	const QString serial = QString::fromStdString(game->info.serial);
	return SearchMatchesApp(QString::fromStdString(game->info.name), serial);
}

void game_list_frame::PopulateGameGrid(int maxCols, const QSize& image_size, const QColor& image_color)
{
	int r = 0;
	int c = 0;

	const std::string selected_item = CurrentSelectionPath();

	// Release old data
	m_game_list->clear_list();
	m_game_grid->deleteLater();

	const bool show_text = m_icon_size_index > gui::game_list_max_slider_pos * 2 / 5;

	if (m_icon_size_index < gui::game_list_max_slider_pos * 2 / 3)
	{
		m_game_grid = new game_list_grid(image_size, image_color, m_margin_factor, m_text_factor * 2, show_text);
	}
	else
	{
		m_game_grid = new game_list_grid(image_size, image_color, m_margin_factor, m_text_factor, show_text);
	}

	// Get list of matching apps
	QList<game_info> matching_apps;

	for (const auto& app : m_game_data)
	{
		if (IsEntryVisible(app))
		{
			matching_apps.push_back(app);
		}
	}

	const int entries = matching_apps.count();

	// Edge cases!
	if (entries == 0)
	{ // For whatever reason, 0%x is division by zero. Absolute nonsense by definition of modulus. But, I'll acquiesce.
		return;
	}

	maxCols = std::clamp(maxCols, 1, entries);

	const int needs_extra_row = (entries % maxCols) != 0;
	const int max_rows = needs_extra_row + entries / maxCols;
	m_game_grid->setRowCount(max_rows);
	m_game_grid->setColumnCount(maxCols);

	for (const auto& app : matching_apps)
	{
		const QString serial = QString::fromStdString(app->info.serial);
		const QString title = m_titles.value(serial, QString::fromStdString(app->info.name));

		game_list_item* item = m_game_grid->addItem(app, title, r, c);
		app->item = item;
		item->setData(gui::game_role, QVariant::fromValue(app));

			item->setToolTip(tr("%0 [%1]").arg(title).arg(serial));
	

		if (selected_item == app->info.path + app->info.icon_path)
		{
			m_game_grid->setCurrentItem(item);
		}

		if (++c >= maxCols)
		{
			c = 0;
			r++;
		}
	}

	if (c != 0)
	{ // if left over games exist -- if empty entries exist
		for (int col = c; col < maxCols; ++col)
		{
			game_list_item* empty_item = new game_list_item();
			empty_item->setFlags(Qt::NoItemFlags);
			m_game_grid->setItem(r, col, empty_item);
		}
	}

	m_game_grid->resizeColumnsToContents();
	m_game_grid->resizeRowsToContents();
	m_game_grid->installEventFilter(this);
	m_game_grid->verticalScrollBar()->installEventFilter(this);
}
void game_list_frame::Refresh(const bool from_drive, const bool scroll_after)
{
	gui::utils::stop_future_watcher(m_repaint_watcher, true);
	gui::utils::stop_future_watcher(m_refresh_watcher, from_drive);

	if (from_drive)
	{
		m_path_list.clear();
		m_game_data.clear();
		m_games.clear();

		//TODO better ATM manually add path from 1 dir to m_paths_list
		QDir parent_folder(QString::fromStdString(QDir::currentPath().toStdString() + "/game/"));
		QFileInfoList fList = parent_folder.entryInfoList(QDir::AllDirs | QDir::NoDotAndDotDot, QDir::DirsFirst);
		foreach(QFileInfo item, fList)
		{
			m_path_list.emplace_back(item.absoluteFilePath().toStdString());
		}

		m_refresh_watcher.setFuture(QtConcurrent::map(m_path_list, [this](const std::string& dir)
		{
				GameInfo game{};
				game.path = dir;
				PSF psf;
				if (psf.open(game.path + "/sce_sys/PARAM.SFO"))
				{
					QString iconpath(QString::fromStdString(game.path) + "/sce_sys/ICON0.PNG");
					game.icon_path = iconpath.toStdString();
					game.name = psf.get_string("TITLE");
					game.serial = psf.get_string("TITLE_ID");
					game.fw = (QString("%1").arg(psf.get_integer("SYSTEM_VER"), 8, 16, QLatin1Char('0'))).mid(1, 3).insert(1, '.').toStdString();
					game.version = psf.get_string("APP_VER");
					game.category = psf.get_string("CATEGORY");

					m_titles.insert(QString::fromStdString(game.serial), QString::fromStdString(game.name));
					
					gui_game_info info{};
					info.info = game;

					m_games.push_back(std::make_shared<gui_game_info>(std::move(info)));
				}
				
		}));
		return;
	}
	// Fill Game List / Game Grid

	if (m_is_list_layout)
	{
		const int scroll_position = m_game_list->verticalScrollBar()->value();
		PopulateGameList();
		SortGameList();
		RepaintIcons();

		if (scroll_after)
		{
			m_game_list->scrollTo(m_game_list->currentIndex(), QAbstractItemView::PositionAtCenter);
		}
		else
		{
			m_game_list->verticalScrollBar()->setValue(scroll_position);
		}
	}
	else
	{
		RepaintIcons();
	}



}
/**
 Cleans and readds entries to table widget in UI.
*/
void game_list_frame::PopulateGameList()
{
	int selected_row = -1;

	const std::string selected_item = CurrentSelectionPath();

	// Release old data
	m_game_grid->clear_list();
	m_game_list->clear_list();

	m_game_list->setRowCount(m_game_data.size());

	int row = 0;
	int index = -1;
	for (const auto& game : m_game_data)
	{
		index++;

		if (!IsEntryVisible(game))
		{
			game->item = nullptr;
			continue;
		}

		const QString serial = QString::fromStdString(game->info.serial);
		const QString title = m_titles.value(serial, QString::fromStdString(game->info.name));

		// Icon
		custom_table_widget_item* icon_item = new custom_table_widget_item;
		game->item = icon_item;
		icon_item->set_icon_func([this, icon_item, game](int)
		{
			icon_item->setData(Qt::DecorationRole, game->pxmap);
			game->pxmap = {};
		});
		
		icon_item->setData(Qt::UserRole, index, true);
		icon_item->setData(gui::custom_roles::game_role, QVariant::fromValue(game));

		// Title
		custom_table_widget_item* title_item = new custom_table_widget_item(title);

		// Serial
		custom_table_widget_item* serial_item = new custom_table_widget_item(serial);

		// Version
		QString app_version = QString::fromStdString(game->info.version);

		m_game_list->setItem(row, gui::column_icon, icon_item);
		m_game_list->setItem(row, gui::column_name, title_item);
		m_game_list->setItem(row, gui::column_serial, serial_item);
		m_game_list->setItem(row, gui::column_firmware, new custom_table_widget_item(game->info.fw));
		m_game_list->setItem(row, gui::column_version, new custom_table_widget_item(app_version));
		m_game_list->setItem(row, gui::column_category, new custom_table_widget_item(game->info.category));
		m_game_list->setItem(row, gui::column_path, new custom_table_widget_item(game->info.path));

		if (selected_item == game->info.path + game->info.icon_path)
		{
			selected_row = row;
		}

		row++;
	}
	m_game_list->setRowCount(row);
	m_game_list->selectRow(selected_row);
}

std::string game_list_frame::CurrentSelectionPath()
{
	std::string selection;

	QTableWidgetItem* item = nullptr;

	if (m_old_layout_is_list)
	{
		if (!m_game_list->selectedItems().isEmpty())
		{
			item = m_game_list->item(m_game_list->currentRow(), 0);
		}
	}
	else if (m_game_grid)
	{
		if (!m_game_grid->selectedItems().isEmpty())
		{
			item = m_game_grid->currentItem();
		}
	}

	if (item)
	{
		if (const QVariant var = item->data(gui::game_role); var.canConvert<game_info>())
		{
			if (const game_info game = var.value<game_info>())
			{
				selection = game->info.path + game->info.icon_path;
			}
		}
	}

	m_old_layout_is_list = m_is_list_layout;

	return selection;
}

void game_list_frame::RepaintIcons(const bool& from_settings)
{
	gui::utils::stop_future_watcher(m_repaint_watcher, true);

	if (from_settings)
	{
		//TODO m_icon_color = gui::utils::get_label_color("gamelist_icon_background_color");
	}

	if (m_is_list_layout)
	{
		QPixmap placeholder(m_icon_size);
		placeholder.fill(Qt::transparent);

		for (auto& game : m_game_data)
		{
			game->pxmap = placeholder;
		}

		// Fixate vertical header and row height
		m_game_list->verticalHeader()->setMinimumSectionSize(m_icon_size.height());
		m_game_list->verticalHeader()->setMaximumSectionSize(m_icon_size.height());

		// Resize the icon column
		m_game_list->resizeColumnToContents(gui::column_icon);

		// Shorten the last section to remove horizontal scrollbar if possible
		m_game_list->resizeColumnToContents(gui::column_count - 1);
	}

	const std::function func = [this](const game_info& game) -> game_list_item*
	{
		if (game->icon.isNull() && (game->info.icon_path.empty() || !game->icon.load(QString::fromStdString(game->info.icon_path))))
		{
			//TODO added warning message if no found
		}
		game->pxmap = PaintedPixmap(game->icon);
		return game->item;
	};
	m_repaint_watcher.setFuture(QtConcurrent::mapped(m_game_data, func));
}

void game_list_frame::FixNarrowColumns() const
{
	qApp->processEvents();

	// handle columns (other than the icon column) that have zero width after showing them (stuck between others)
	for (int col = 1; col < m_columnActs.count(); ++col)
	{
		if (m_game_list->isColumnHidden(col))
		{
			continue;
		}

		if (m_game_list->columnWidth(col) <= m_game_list->horizontalHeader()->minimumSectionSize())
		{
			m_game_list->setColumnWidth(col, m_game_list->horizontalHeader()->minimumSectionSize());
		}
	}
}

void game_list_frame::ResizeColumnsToContents(int spacing) const
{
	if (!m_game_list)
	{
		return;
	}

	m_game_list->verticalHeader()->resizeSections(QHeaderView::ResizeMode::ResizeToContents);
	m_game_list->horizontalHeader()->resizeSections(QHeaderView::ResizeMode::ResizeToContents);

	// Make non-icon columns slighty bigger for better visuals
	for (int i = 1; i < m_game_list->columnCount(); i++)
	{
		if (m_game_list->isColumnHidden(i))
		{
			continue;
		}

		const int size = m_game_list->horizontalHeader()->sectionSize(i) + spacing;
		m_game_list->horizontalHeader()->resizeSection(i, size);
	}
}

void game_list_frame::OnHeaderColumnClicked(int col)
{
	if (col == 0) return; // Don't "sort" icons.

	if (col == m_sort_column)
	{
		m_col_sort_order = (m_col_sort_order == Qt::AscendingOrder) ? Qt::DescendingOrder : Qt::AscendingOrder;
	}
	else
	{
		m_col_sort_order = Qt::AscendingOrder;
	}
	m_sort_column = col;

	m_gui_settings->SetValue(gui::game_list_sortAsc, m_col_sort_order == Qt::AscendingOrder);
	m_gui_settings->SetValue(gui::game_list_sortCol, col);

	SortGameList();
}

void game_list_frame::SortGameList() const
{
	// Back-up old header sizes to handle unwanted column resize in case of zero search results
	QList<int> column_widths;
	const int old_row_count = m_game_list->rowCount();
	const int old_game_count = m_game_data.count();

	for (int i = 0; i < m_game_list->columnCount(); i++)
	{
		column_widths.append(m_game_list->columnWidth(i));
	}

	// Sorting resizes hidden columns, so unhide them as a workaround
	QList<int> columns_to_hide;

	for (int i = 0; i < m_game_list->columnCount(); i++)
	{
		if (m_game_list->isColumnHidden(i))
		{
			m_game_list->setColumnHidden(i, false);
			columns_to_hide << i;
		}
	}

	// Sort the list by column and sort order
	m_game_list->sortByColumn(m_sort_column, m_col_sort_order);

	// Hide columns again
	for (auto i : columns_to_hide)
	{
		m_game_list->setColumnHidden(i, true);
	}

	// Don't resize the columns if no game is shown to preserve the header settings
	if (!m_game_list->rowCount())
	{
		for (int i = 0; i < m_game_list->columnCount(); i++)
		{
			m_game_list->setColumnWidth(i, column_widths[i]);
		}

		m_game_list->horizontalHeader()->setSectionResizeMode(gui::column_icon, QHeaderView::Fixed);
		return;
	}

	// Fixate vertical header and row height
	m_game_list->verticalHeader()->setMinimumSectionSize(m_icon_size.height());
	m_game_list->verticalHeader()->setMaximumSectionSize(m_icon_size.height());
	m_game_list->resizeRowsToContents();

	// Resize columns if the game list was empty before
	if (!old_row_count && !old_game_count)
	{
		ResizeColumnsToContents();
	}
	else
	{
		m_game_list->resizeColumnToContents(gui::column_icon);
	}

	// Fixate icon column
	m_game_list->horizontalHeader()->setSectionResizeMode(gui::column_icon, QHeaderView::Fixed);

	// Shorten the last section to remove horizontal scrollbar if possible
	m_game_list->resizeColumnToContents(gui::column_count - 1);
}

QPixmap game_list_frame::PaintedPixmap(const QPixmap& icon) const
{
	const qreal device_pixel_ratio = devicePixelRatioF();
	QSize canvas_size(320, 176);
	QSize icon_size(icon.size());
	QPoint target_pos;

	if (!icon.isNull())
	{
		// Let's upscale the original icon to at least fit into the outer rect of the size of PS3's ICON0.PNG
		if (icon_size.width() < 320 || icon_size.height() < 176)
		{
			icon_size.scale(320, 176, Qt::KeepAspectRatio);
		}

		canvas_size = icon_size;

		// Calculate the centered size and position of the icon on our canvas.
		if (icon_size.width() != 320 || icon_size.height() != 176)
		{
			constexpr double target_ratio = 320.0 / 176.0; // aspect ratio 20:11

			if ((icon_size.width() / static_cast<double>(icon_size.height())) > target_ratio)
			{
				canvas_size.setHeight(std::ceil(icon_size.width() / target_ratio));
			}
			else
			{
				canvas_size.setWidth(std::ceil(icon_size.height() * target_ratio));
			}

			target_pos.setX(std::max<int>(0, (canvas_size.width() - icon_size.width()) / 2.0));
			target_pos.setY(std::max<int>(0, (canvas_size.height() - icon_size.height()) / 2.0));
		}
	}

	// Create a canvas large enough to fit our entire scaled icon
	QPixmap canvas(canvas_size * device_pixel_ratio);
	canvas.setDevicePixelRatio(device_pixel_ratio);
	canvas.fill(m_icon_color);

	// Create a painter for our canvas
	QPainter painter(&canvas);
	painter.setRenderHint(QPainter::SmoothPixmapTransform);

	// Draw the icon onto our canvas
	if (!icon.isNull())
	{
		painter.drawPixmap(target_pos.x(), target_pos.y(), icon_size.width(), icon_size.height(), icon);
	}

	// Finish the painting
	painter.end();

	// Scale and return our final image
	return canvas.scaled(m_icon_size * device_pixel_ratio, Qt::KeepAspectRatio, Qt::TransformationMode::SmoothTransformation);
}
void game_list_frame::SetListMode(const bool& is_list)
{
	m_old_layout_is_list = m_is_list_layout;
	m_is_list_layout = is_list;

	m_gui_settings->SetValue(gui::game_list_listMode, is_list);

	Refresh(true);

	m_central_widget->setCurrentWidget(m_is_list_layout ? m_game_list : m_game_grid);
}
void game_list_frame::SetSearchText(const QString& text)
{
	m_search_text = text;
	Refresh();
}
void game_list_frame::closeEvent(QCloseEvent* event)
{
	QDockWidget::closeEvent(event);
	Q_EMIT GameListFrameClosed();
}

void game_list_frame::resizeEvent(QResizeEvent* event)
{
	if (!m_is_list_layout)
	{
		Refresh(false, m_game_grid->selectedItems().count());
	}
	QDockWidget::resizeEvent(event);
}
void game_list_frame::ResizeIcons(const int& slider_pos)
{
	m_icon_size_index = slider_pos;
	m_icon_size = gui_settings::SizeFromSlider(slider_pos);

	RepaintIcons();
}

void game_list_frame::LoadSettings()
{
	m_col_sort_order = m_gui_settings->GetValue(gui::game_list_sortAsc).toBool() ? Qt::AscendingOrder : Qt::DescendingOrder;
	m_sort_column = m_gui_settings->GetValue(gui::game_list_sortCol).toInt();

	Refresh(true);

	const QByteArray state = m_gui_settings->GetValue(gui::game_list_state).toByteArray();
	if (!m_game_list->horizontalHeader()->restoreState(state) && m_game_list->rowCount())
	{
		// If no settings exist, resize to contents.
		ResizeColumnsToContents();
	}

	for (int col = 0; col < m_columnActs.count(); ++col)
	{
		const bool vis = m_gui_settings->GetGamelistColVisibility(col);
		m_columnActs[col]->setChecked(vis);
		m_game_list->setColumnHidden(col, !vis);
	}
	SortGameList();
	FixNarrowColumns();

	m_game_list->horizontalHeader()->restoreState(m_game_list->horizontalHeader()->saveState());

}

void game_list_frame::SaveSettings()
{
	for (int col = 0; col < m_columnActs.count(); ++col)
	{
		m_gui_settings->SetGamelistColVisibility(col, m_columnActs[col]->isChecked());
	}
	m_gui_settings->SetValue(gui::game_list_sortCol, m_sort_column);
	m_gui_settings->SetValue(gui::game_list_sortAsc, m_col_sort_order == Qt::AscendingOrder);
	m_gui_settings->SetValue(gui::game_list_state, m_game_list->horizontalHeader()->saveState());
}

/**
* Returns false if the game should be hidden because it doesn't match search term in toolbar.
*/
bool game_list_frame::SearchMatchesApp(const QString& name, const QString& serial) const
{
	if (!m_search_text.isEmpty())
	{
		const QString search_text = m_search_text.toLower();
		return m_titles.value(serial, name).toLower().contains(search_text) || serial.toLower().contains(search_text);
	}
	return true;
}
