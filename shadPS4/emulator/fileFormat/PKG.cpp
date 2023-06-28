#include "PKG.h"
#include "../../core/FsFile.h"
#include <direct.h> 
#include <QString>
#include <QDir>
#include <QMessageBox>


PKG::PKG()
{

}

PKG::~PKG()
{
}

char* PKG::get_ekpkg(EntryKeys entrykeys, char* imagekey)
{
	char* dk3 = rsa2048decrypt(entrykeys.Keys[3].key, DPrivateExponent, DExponent1, DExponent2, DPublicExponent, DCoefficient, DModulus, DPrime1, DPrime2);
	char* imageKeyDec = imagekey;
	char* iv_key = PKG::SHA256()
}

char* PKG::rsa2048decrypt(char* cipher, char* PrivateExponent, char* Exponent1, char* Exponent2, char* PublicExponent, char* Coefficient, char* Modulus, char* Prime1, char* Prime2)
{
	AutoSeededRandomPool rng;
	InvertibleRSAFunction params;
	params.SetPrime1(Integer(reinterpret_cast<const char*>(Prime1)));
	params.SetPrime2(Integer(reinterpret_cast<const char*>(Prime2)));
	params.SetPublicExponent(Integer(reinterpret_cast<const char*>(PublicExponent)));
	params.SetPrivateExponent(Integer(reinterpret_cast<const char*>(PrivateExponent)));
	params.SetModPrime1PrivateExponent(Integer(reinterpret_cast<const char*>(Exponent1)));
	params.SetModPrime2PrivateExponent(Integer(reinterpret_cast<const char*>(Exponent2)));
	params.SetModulus(Integer(reinterpret_cast<const char*>(Modulus)));
	params.SetMultiplicativeInverseOfPrime2ModPrime1(Integer(reinterpret_cast<const char*>(Coefficient)));
	RSA::PrivateKey privKey(params);
	RSAES_OAEP_SHA_Decryptor dec(privKey);
	string decrypted_data;
	StringSource(reinterpret_cast<const char*>(cipher), new PK_DecryptorFilter(rng, dec, new StringSink(decrypted_data)));
	char* rs = new char[decrypted_data.length() + 1];
	strcpy(rs, decrypted_data.c_str());
	return rs;
}

char* PKG::SHA256(char* data, U32 size)
{
	CryptoPP::byte const* pbData = (CryptoPP::byte*)data;
	CryptoPP::byte abDigest[CryptoPP::SHA256::DIGESTSIZE];

	CryptoPP::SHA256().CalculateDigest(abDigest, pbData, size);

	return (char*)abDigest;
}

bool PKG::ignoreFile(U32 fileID)
{
	switch (fileID)
	{
	default:
		return 0;
	case 0x0001: 
		return 1; //digests
	case 0x0010:
		return 1; //entry_keys
	case 0x0020:
		return 1; //image_key
	case 0x0080:
		return 1; //general_digests
	case 0x0100:
		return 1; //metas
	case 0x0200:
		return 1; //entry_names
	case 0x0400:
		return 1; //license.dat
	case 0x0401:
		return 1; //license.info
	case 0x0409:
		return 1; //psreserved.dat
	case 0x1001:
		return 1; //playgo-chunk.dat
	case 0x1002:
		return 1; //playgo-chunk.sha
	case 0x1003:
		return 1; //playgo-manifest.xml
	}
}

bool PKG::open(const string& filepath) {
	FsFile file;
	if (!file.Open(filepath, fsRead))
	{
		return false;
	}
	pkgSize = file.getFileSize();
	PKGHeader pkgheader;
	file.ReadBE(pkgheader);
	//we have already checked magic should be ok

	//find title id it is part of pkg_content_id starting at offset 0x40
	file.Seek(0x47, fsSeekSet);//skip first 7 characters of content_id 
	file.Read(&pkgTitleID, sizeof(pkgTitleID));

	file.Close();

	return true;
}
bool PKG::extract(const string& filepath, const string& extractPath, string& failreason)
{
		this->extractPath = extractPath;
		FsFile file;
		if (!file.Open(filepath, fsRead))
		{
			return false;
		}
		pkgSize = file.getFileSize();
		PKGHeader pkgheader;
		file.ReadBE(pkgheader);

		if (pkgheader.pkg_size > pkgSize)
		{
			failreason = "PKG file size is different";
			return false;
		}
		if ((pkgheader.pkg_content_size + pkgheader.pkg_content_offset) > pkgheader.pkg_size)
		{
			failreason = "Content size is bigger than pkg size";
			return false;
		}
		file.Seek(0, fsSeekSet);
		pkg = (U08*)mmap(pkgSize, file.fileDescr());
		if (pkg == nullptr)
		{
			failreason = "Can't allocate size for image";
			return false;
		}

		file.Read(pkg, pkgSize);
		
		U32 offset = pkgheader.pkg_table_entry_offset;
		U32 n_files = pkgheader.pkg_table_entry_count;

		char* imagekey;
		U32 entrykeyOffset;
		for (int i = 0; i < n_files; i++) {
			PKGEntry entry = (PKGEntry&)pkg[offset + i * 0x20];
			ReadBE(entry);
			//try to figure out the name
			string name = getEntryNameByType(entry.id);
			if (!name.empty() && !ignoreFile(entry.id))
			{
				QString filepath= QString::fromStdString(extractPath+ "/sce_sys/" + name);
				QDir dir = QFileInfo(filepath).dir();
				if (!dir.exists()) {
					dir.mkpath(dir.path());
				}
				FsFile out;
				out.Open(extractPath + "/sce_sys/" + name, fsWrite);
				out.Write(pkg + entry.offset, entry.size);
				out.Close();
			}
			else if (ignoreFile(entry.id))
			{
				if (name == "entry_keys")
					entrykeyOffset = entry.offset;
				else if (name == "image_key")
				{
					file.Seek(entry.offset, fsSeekSet);
					file.Read(imagekey, entry.size);
				}
			}
			else
			{
				//just print with id
				FsFile out;
				out.Open(extractPath + "/sce_sys/" + to_string(entry.id), fsWrite);
				out.Write(pkg + entry.offset, entry.size);
				out.Close();
			}
		}
		EntryKeys entryKeys(entrykeyOffset, file);
		get_ekpkg(entryKeys, imagekey);
		//extract pfs_image.dat
		FsFile out;
		out.Open(extractPath + "pfs_image.dat", fsWrite);
		out.Write(pkg + pkgheader.pfs_image_offset, pkgheader.pfs_image_size);
		out.Close();
		munmap(pkg);
		return true;
}