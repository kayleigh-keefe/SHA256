#include "Sha256.h"

// Standard libraries
#include <cassert>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

static const std::unordered_map<std::string, std::string> hashes =
{
   {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
   {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
   {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
   {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
   {"1 million \'a\'s", "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"}
};

std::string vectorToHexString(const std::vector<uint32_t>& hash)
{
   std::stringstream ss;

   // Set formatting: hex, zero-padded to 8 characters, lowercase
   ss << std::hex << std::setfill('0');
    
   for (uint32_t word : hash)
   {
      ss << std::setw(8) << word;
   }

   // Reset back to decimal if needed later
   std::cout << std::dec << std::endl;

   return ss.str();
}

int main(int argc, char* argv[])
{
   Sha256 hasher;

   if (argc == 1)
   {
      for (const auto& [key, answer]: hashes)
      {
         std::string input = key;
         std::cout << "Testing case: " << key << std::endl;
         if (input == "1 million \'a\'s")
         {
            std::string million_as(1000000, 'a');
            input = million_as;
         }
         size_t len = input.length();
         std::cout << "len: " << len << std::endl;
         std::vector<uint32_t> hash = hasher.process(input.c_str(), len);
         const std::string hash_str = vectorToHexString(hash);
         std::cout << "Expected value: " << answer << std::endl;
         std::cout << "Actual value: " << hash_str << std::endl << std::endl;
         assert(hash_str == answer);
      }
   }
   else if (argc == 2)
   {
      char* input = argv[1];
      // There is no way to dynamically interpret straight from a char*
      // what its size is.
      size_t len = std::strlen(input);
      std::vector<uint32_t> hash = hasher.process(input, len);
      std::cout << "input: " << input << "; SHA256 hash: ";
      // Set the output to hexadecimal mode
      std::cout << vectorToHexString(hash) << std::endl;
   }
   else
   {
      throw std::invalid_argument("Expected exactly 1 or 2 arguments, received " + std::to_string(argc));
   }

   return 0;
}