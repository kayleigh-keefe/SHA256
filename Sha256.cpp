#include "Sha256.h"
#include <cmath>
#include <endian.h>
#include <iomanip>
#include <iostream>

// SHA-256 processes 512-bit Chunks, which are then expanded into 64 32-bit Words (16×32=512).

Sha256::Sha256()
{
   detectEndianness();
}

Sha256::~Sha256()
{
}

std::vector<uint32_t> Sha256::process(const char* raw_data, const size_t len)
{
   this->reset();  // Ensure remnants of previous hashes are cleared
   // Convert the character array into a standard vector
   std::vector<uint8_t> padded_msg = pad(raw_data, len);
   std::cout << "padded message length: " << padded_msg.size();
   // Process the message in 512-successive chunks:
   uint8_t words_per_chunk = 64;  // 1 word = 8 bits; 64 * 8 = 512
   uint64_t num_chunks = std::ceil(padded_msg.size()/words_per_chunk);

   std::vector<uint32_t> words;

   for (int chunk_num=0; chunk_num<num_chunks; chunk_num++)
   {
      std::vector<uint8_t> chunk(padded_msg.begin() + (64*chunk_num), padded_msg.begin() + (64*(chunk_num+1)));
      
      words = cnvrt2BigEndianW(chunk);

      this->expand16To64(words);

      this->compress(words);
   }

   std::vector<uint32_t> hash = {h0, h1, h2, h3, h4, h5, h6, h7};
   return hash;
}

std::vector<uint8_t> Sha256::pad(const char* raw_data, uint64_t size)
{
   std::vector<uint8_t> padded_msg(raw_data, raw_data + size);
   // Append a single '1' bit -- within a byte-oriented system,
   // and since we are assuming Big Endian architecture, we are
   // appending 10000000, or 0x80. This is an indicator of where
   // the data ends.
   padded_msg.push_back(0x80);
   // Append null bytes so that the new size of the digest is a
   // multiple of 64.
   while ((padded_msg.size() % 64) != 56)  // The reason we use 56 and not 64 is because
   {                                       // the last 8 bytes are reserved for the length.
        padded_msg.push_back(0x00);
   }
   // Append original length as 64-bit Big Endian integer. It is important to note that
   // FIPS 180-4 requires bit-count rather than byte-coount.
   uint64_t size_in_bits = size * 8;
   for (int i = 7; i >=0; --i)
   {
      // Shift right by i*8 bits and mask with 0xFF to isolate the byte
      uint8_t byte = static_cast<uint8_t>((size_in_bits >> (i * 8)) & 0xFF);
      padded_msg.push_back(byte);
   }

   return padded_msg;
}

// Per FIPS 180-4, SHA-256 specification dictates words to be
// defined as 32-bit blocks.
std::vector<uint32_t> Sha256::cnvrt2BigEndianW(const std::vector <uint8_t> raw_data)
{
   // Ensure input is a multiple of 4 bytes (after padding)
   size_t num_words = raw_data.size()/4;
   std::vector<uint32_t> words(num_words);

   for (size_t i = 0; i < num_words; ++i)
   {
      uint32_t word = (raw_data[4*i] << 24) | (raw_data[(4*i)+1] << 16) | (raw_data[(4*i)+2] << 8) | raw_data[(4*i)+3];
      words[i] = word;
   }

   return words;
}

void Sha256::detectEndianness()
{
    uint32_t num = 1;
    // Cast the address of the 4-byte integer to a 1-byte pointer
    uint8_t* bytePtr = reinterpret_cast<uint8_t*>(&num);
    
    // If the first byte is 1, it's Little Endian
    this->is_little_endian = (*bytePtr == 1);
}

void Sha256::expand16To64(std::vector<uint32_t>& words)
{
   //for i from 16 to 63
   //   s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
   //   s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
   //   w[i] := w[i-16] + s0 + w[i-7] + s1
   words.resize(64); // Pre-allocate to 64
   for (int i=16; i < 64; ++i)
   {
      // Message schedule expansion: using SHA-256 constants (7, 18, 3 and 17, 19, 10).
      // These offsets balance 'aggressive' bit-mixing (odd rotations) with 'lane-restricted' 
      // pulsing (even rotations) to ensure maximum diffusion (the avalanche effect).
      //
      // XOR provides information-preserving mixing, while modular addition breaks 
      // the linearity of XOR, preventing predictable algebraic relationships that 
      // could be exploited by cryptanalysis.
      uint32_t s0 = this->rightRotate(words[i-15], 7) ^ this->rightRotate(words[i-15], 18) ^ (words[i-15] >> 3);
      uint32_t s1 = this->rightRotate(words[i-2], 17) ^ this->rightRotate(words[i-2], 19) ^ (words[i-2] >> 10);
      //words.push_back(words[i-16] + s0 + words[i-7] + s1);
      words[i] = words[i-16] + s0 + words[i-7] + s1;
   }
}

uint32_t Sha256::rightRotate(uint32_t word, uint32_t offset)
{
   uint32_t mod_offset = offset%32;
   uint32_t rotated = word;
   if (mod_offset != 0)
   {
      uint32_t wraparound = word << (32-mod_offset);
      rotated = (word>>mod_offset) | wraparound;
   }

   return rotated;
}

void Sha256::compress(const std::vector<uint32_t> words)
{
   //Initialize working variables to current hash value:
   uint32_t a = this->h0;
   uint32_t b = this->h1;
   uint32_t c = this->h2;
   uint32_t d = this->h3;
   uint32_t e = this->h4;
   uint32_t f = this->h5;
   uint32_t g = this->h6;
   uint32_t h = this->h7;
   for (int i = 0; i < 64; ++i)
   {
      /*
        Compression function main loop:
        for i from 0 to 63
           S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
           ch := (e and f) xor ((not e) and g)
           temp1 := h + S1 + ch + k[i] + w[i]
           S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
           maj := (a and b) xor (a and c) xor (b and c)
           temp2 := S0 + maj
 
           h := g
           g := f
           f := e
           e := d + temp1
           d := c
           c := b
           b := a
           a := temp1 + temp2
      */
      
      // Note: The calues 6, 11, 25 (for S1) or 2, 13, 22 (for S0) were tuned with computer-aided
      // cryptanalysis.
      uint32_t S1 = this->rightRotate(e, 6) ^ this->rightRotate(e, 11) ^ this->rightRotate(e, 25);
      uint32_t ch = (e & f) ^ ((~e) & g);
      uint32_t temp1 = h + S1 + ch + this->k[i] + words[i];
      uint32_t S0 = this->rightRotate(a, 2) ^ this->rightRotate(a, 13) ^ this->rightRotate(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = S0 + maj;
      
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
   }
   // Add the compressed chunk to the current hash value:
   h0 = h0 + a;
   h1 = h1 + b;
   h2 = h2 + c;
   h3 = h3 + d;
   h4 = h4 + e;
   h5 = h5 + f;
   h6 = h6 + g;
   h7 = h7 + h;
}

void Sha256::reset()
{
   h0 = h0_init;
   h1 = h1_init;
   h2 = h2_init;
   h3 = h3_init;
   h4 = h4_init;
   h5 = h5_init;
   h6 = h6_init;
   h7 = h7_init;
}
