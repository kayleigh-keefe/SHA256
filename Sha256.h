// Key points:
//
// Properties to create a good one-way function: 
//   * Non-linearity: (Achieved via Add + XOR)
//   * Diffusion: (Achieved via Rotations and Shifts)
//   * Irreversibility: (Achieved via the Davies-Meyer construction)

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

// It is important to note that binary is represented in Big Endian format.
class Sha256
{
public:

   // Default constructor/destructor
   Sha256();
   ~Sha256();

   std::vector<uint32_t> process(const char* rawData, const size_t len);
   
private:
   // First 32 bits of the fractional parts of the square roots of the first 8 primes 2..19.
   // The reason only the decimal parts of the square roots is because the integer portion of
   // the number is a predictable pattern. However, the decimal portion is not. It is a high-
   // entropy quantity, a property which is crucial to the irreversability of the algorithm.

   // Example:
   // sqrt(2) = 1.4142135623730950488...
   // Fractional part = 0.4142135623730950488...
   // To convert this decimal fraction into a 32-bit unsigned integer word, the fraction is
   // multiplied by 2^32 (which shifts the binary point 32 places to the right):
   // 0.4142135623730950488*4,294,967,296=1,779,033,703.95
   // Drop the remainder (take the floor): 1,779,033,703
   // Converting 1,779,033,703 to hexadecimal gives 0x6A09E667.
   static constexpr uint32_t h0_init = 0x6a09e667;  // sqrt(2) decimal portion 
   static constexpr uint32_t h1_init = 0xbb67ae85;  // sqrt(3) decimal portion
   static constexpr uint32_t h2_init = 0x3c6ef372;  // sqrt(5) decimal portion
   static constexpr uint32_t h3_init = 0xa54ff53a;  // sqrt(7) decimal portion
   static constexpr uint32_t h4_init = 0x510e527f;  // sqrt(11) decimal portion
   static constexpr uint32_t h5_init = 0x9b05688c;  // sqrt(13) decimal portion
   static constexpr uint32_t h6_init = 0x1f83d9ab;  // sqrt(17) decimal portion
   static constexpr uint32_t h7_init = 0x5be0cd19;  // sqrt(19) decimal portion
   uint32_t h0 = h0_init;
   uint32_t h1 = h1_init;
   uint32_t h2 = h2_init;
   uint32_t h3 = h3_init;
   uint32_t h4 = h4_init;
   uint32_t h5 = h5_init;
   uint32_t h6 = h6_init;
   uint32_t h7 = h7_init;


   // First 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311.
   // These are round-specific noise. One constant is used for every single round of the 64-round loop.
   // Because we're looping 64 times, 64 unique values are needed to ensure that each round performs a
   // distinct mathematical operation.

   // Example:
   // cbrt(2) = 1.259921049894873165...
   // Fractional part = 0.259921049894873165...
   // To convert this decimal fraction into a 32-bit unsigned integer word, the fraction is
   // multiplied by 2^32 (which shifts the binary point 32 places to the right):
   // 0.259921049894873165*×4,294,967,296=1,116,352,408.840464482
   // Drop the remainder (take the floor): 1,116,352,408
   // Converting 1,116,352,408 to hexadecimal gives 0x428a2f98.
   std::array<uint32_t,64> k = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, // cbrt(2),   cbrt(3),   cbrt(5),   cbrt(7),   cbrt(11),  cbrt(13)  decimal portions
                                0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, // cbrt(17),  cbrt(19),  cbrt(35),  cbrt(29),  cbrt(31),  cbrt(37)  decimal portions
                                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, // cbrt(41),  cbrt(43),  cbrt(47),  cbrt(53),  cbrt(59),  cbrt(61)  decimal portions
                                0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, // cbrt(67),  cbrt(71),  cbrt(73),  cbrt(79),  cbrt(83),  cbrt(89)  decimal portions
                                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, // cbrt(97),  cbrt(101), cbrt(103), cbrt(107), cbrt(109), cbrt(113) decimal portions
                                0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, // cbrt(127), cbrt(131), cbrt(137), cbrt(139), cbrt(149), cbrt(151) decimal portions
                                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, // cbrt(157), cbrt(163), cbrt(167), cbrt(173), cbrt(179), cbrt(181) decimal portions
                                0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, // cbrt(191), cbrt(193), cbrt(197), cbrt(199), cbrt(211), cbrt(223) decimal portions
                                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, // cbrt(227), cbrt(229), cbrt(233), cbrt(239), cbrt(241), cbrt(251) decimal portions
                                0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, // cbrt(257), cbrt(263), cbrt(269), cbrt(271), cbrt(277), cbrt(281) decimal portions
                                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};                        // cbrt(283), cbrt(293), cbrt(307), cbrt(311) decimal portions

   bool is_little_endian = false;

   std::vector<uint8_t> pad(const char* rawData, uint64_t size);

   std::vector<uint32_t> cnvrt2BigEndianW(const std::vector <uint8_t> raw_data);

   void detectEndianness();

   void expand16To64(std::vector<uint32_t>& words);

   uint32_t rightRotate(uint32_t word, uint32_t offset);

   void compress(const std::vector<uint32_t> words);

   void reset();
};