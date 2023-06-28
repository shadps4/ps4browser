#include "EntryKeys.h"
EntryKeys::EntryKeys(U32 offset, FsFile file)
{
	file.Seek(offset, fsSeekSet);
	file.Read(seedDigest, 32);
	for (int i = 0; i < 7; i++)
	{
		file.Read(Keys[i].digest, 32);
		file.Read(Keys[i].key, 256);
	}
}
EntryKeys::~EntryKeys()
{

}