#include "../../Types.h"
#include <stdio.h>
#include "../../core/FsFile.h"
using namespace std;
class PkgEntryKey {
public:
	char digest[32];
	char key[256];
};
class EntryKeys
{
public:
	EntryKeys(U32 offset, FsFile file);
	~EntryKeys();
	char* seedDigest;
	PkgEntryKey Keys[7];
};

