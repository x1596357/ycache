#include "md5.h"
#include <unordered_set>
#include <fstream>
#include <cstdlib>

using namespace std;

bool isAllZeros(char *buf, int size) {
  for (int i = 0; i < size; i++) {
    if (buf[i] != 0) {
      return false;
    }
  }

  return true;
}

// ./getDuplicateRate FILE BLOCKSIZE INCLUDE_ZEROS
// For example:
// ./getDuplicateRate dump 4096 0
int main(int argc, char const *argv[]) {
  if (argc != 4) {
    cout << "Usage:" << argv[0]
         << " FILE BLOCKSIZE(1~INT_MAX) INCLUDE_ZEROS(0~1)" << endl;
    cout << "For example:" << endl;
    cout << argv[0] << " dump 4096 0" << endl;
  }

  ifstream file(argv[1], ios::binary | ios::ate);
  int blockSize = 0;
  int includeZeros = 0;
  if (!file.is_open()) {
    cerr << "Open " << argv[1] << " failed" << endl;
    return -1;
  } else {
    cout << "File size :" << file.tellg() << " byte(s)" << endl;
    blockSize = atoi(argv[2]);
    cout << "Block size :" << blockSize << " byte(s)" << endl;
    includeZeros = atoi(argv[3]);
    if (includeZeros == 0) {
      cout << "Zeros :not included" << endl;
    } else {
      cout << "Zeros :included" << endl;
    }
  }

  // Start getting duplication rate
  char *block = new char[blockSize];
  unsigned long long blockCount = 0;
  unordered_set<string> unset;
  file.seekg(0, ios::beg);
  while (file.read(block, blockSize)) {
    if (includeZeros != 0 || !isAllZeros(block, blockSize)) {
      MD5 md5;
      md5.update(block, blockSize);
      md5.finalize();
      unset.insert(md5.hexdigest());
      blockCount++;
    }
  }
  delete[] block;

  unsigned long unsetSize = unset.size();
  cout << "Total blocks :" << blockCount << endl;
  cout << "Unique blocks :" << unsetSize << endl;
  cout << "Duplicate blocks :" << blockCount - unsetSize << endl;
  long double duplicateRate = 1 - (long double)unsetSize / blockCount;
  cout << "Duplicate rate :" << duplicateRate * 100 << '%' << endl;
  return 0;
}