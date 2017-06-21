# Available online at http://man.as/trivium-crystal-utnfrba
require "stumpy_png"
# require "stumpy_core"

key = (ENV["TRIVIUM_KEY"]? || "00010203040506070809").hexbytes
init_v = (ENV["TRIVIUM_IV"]? || "1112131415161718191a").hexbytes

def bit(source : Slice, index)
  source = source.as(Slice(UInt8))
  byte_index, bit_index = index.divmod(8)
  (source[byte_index] << (7 - bit_index)) >> 7
end

# get bit indexed with base 1
def bit1(source, index)
  bit(source, index - 1)
end

class Trivium
  @state : Bytes

  def initialize(@key : Bytes, @iv : Bytes)
    raise "Key must be 10 bytes long" unless key.bytesize == 10
    raise "Init vector must be 10 bytes long" unless @iv.bytesize == 10
    puts "Using key #{@key.hexstring}"
    puts "Using IV #{@iv.hexstring}"
    @counter = 0
    @state = initial_state(@key, @iv)
  end

  def initial_state(key, iv) : Bytes
    state = Bytes.new(36, 0u8)
    # {s1..s80} <- {k1..k80} - but the spec is 1-based 😞
    (0..9).each { |i| state[i] = key[i] }

    # {s94..s173} <- {iv1..iv80}
    # BUT s94 is the fifth bit of byte 11 (0-based)
    # so we copy bytes by shifting them 😵🔫
    state[11] = (iv[0] >> 5)
    (0..8).each { |i| state[12 + i] = ((iv[i] << 3) | (iv[i + 1] >> 5)) }
    state[21] = iv[9] << 3

    # Then the last 3 bits are 1's 🤷‍
    state[35] = 0b111u8

    # rotate state for 4 full cycles
    (4*288).times { next_bit(state) }

    # And there's our state! 🎉
    state
  end

  def next_bit(state : Bytes = @state)
    t1 = bit1(state, 66) ^ bit1(state, 93)
    t2 = bit1(state, 162) ^ bit1(state, 177)
    t3 = bit1(state, 243) ^ bit1(state, 288)
    z = t1 ^ t2 ^ t3
    t1 = t1 ^ (bit1(state, 91) & bit1(state, 92)) ^ bit1(state, 171)
    t2 = t2 ^ (bit1(state, 175) & bit1(state, 176)) ^ bit1(state, 264)
    t3 = t3 ^ (bit1(state, 286) & bit1(state, 287)) ^ bit1(state, 69)

    # shift every byte one bit
    35.downto(1).each { |i|
      state[i] = (state[i] << 1) | (state[i - 1] >> 7)
    }
    state[0] = state[0] << 1

    # assign bits s1, s94 and s178 to t3, t1 and t2 respectively
    state[0] = state[0] | t3

    # s94 is bit 5 of byte 11
    state[11] = (state[11] & 0b1101_1111) | (t1 << 5)

    # s178 is bit 1 of byte 22
    state[22] = (state[22] & 0b1111_1101) | (t2 << 1)

    # return the z bit
    z
  end

  def next_byte
    k = 0u8
    8.times { k = (k << 1) | next_bit }
    k
  end

  def next_2bytes : UInt16
    ((0u16 + next_byte) << 8) | next_byte
  end

  def cipher(message : Bytes)
    result = Bytes.new(message.size)
    message.each_with_index { |m, i| result[i] = m ^ next_byte }
    result
  end

  def cipher(message : StumpyCore::RGBA)
    StumpyCore::RGBA.new(
      next_2bytes ^ message.r,
      next_2bytes ^ message.g,
      next_2bytes ^ message.b,
      next_2bytes ^ message.a
    )
  end
end

raise "Usage: trivium [--png] input_file output_file" unless [2, 3].includes? ARGV.size

is_png = false

if ARGV[0] == "--png"
  is_png = true
  source_file = ARGV[1]
  dest_file = ARGV[2]
else
  source_file = ARGV[0]
  dest_file = ARGV[1]
end

trivium = Trivium.new(key, init_v)
if is_png
  input_image = StumpyPNG.read(source_file)
  ciphered_image = StumpyCore::Canvas.new(input_image.width, input_image.height) { |x, y|
    trivium.cipher(input_image[x, y])
  }
  StumpyPNG.write(ciphered_image, dest_file)
else
  File.open(source_file) { |source|
    File.write(dest_file, trivium.cipher(source.gets_to_end.to_slice))
  }
end
