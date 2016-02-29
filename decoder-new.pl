#!/usr/bin/perl
use Crypt::Rijndael;
use Crypt::ECB;

my $crypt = Crypt::ECB->new;
my $pseudonym = $ARGV[0];

# Change this key to what your 3GPP-AAA server is using for the encryption key
my $crypt->key('0000000000000000');

$crypt->cipher('Rijndael') || die $crypt->errstring;

# print "Processing Pseudonym: $pseudonym\n";
$pseudonym_length = length($pseudonym);
# print "Length of pseudonym (should be 23): " . $pseudonym_length . "\n";


##### Load BASE64 table
# print "Loading base64 table\n";
$upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
$lower_case = 'abcdefghijklmnopqrstuvwxyz';
$numbers = '0123456789+/';
#print "Loading $upper_case\n";
for ($p_count= 0; $p_count < 26; $p_count++) {
  $base64[$p_count] = substr($upper_case,$p_count,1);
}
#print "Loading $lower_case\n";
for ($p_count=26; $p_count < 52; $p_count++) {
  $base64[$p_count] = substr($lower_case,($p_count-26),1);
}
#print "Loading $numbers\n";
for ($p_count=52; $p_count < 64; $p_count++) {
  $base64[$p_count] = substr($numbers,($p_count-52),1);
}
#####

##### Convert pseudonym to bits
# print "Applying base64 decoding to pseudonym to retreive binary format\n";
$pseudonym_bits = "";
for ($count=0;$count < $pseudonym_length; $count++) {
  $byte = substr($pseudonym, $count, 1);
  $bit_string = base64a2b($byte);
  $pseudonym_bits = $pseudonym_bits . $bit_string;
}
$pseudonym_bit_length = length($pseudonym_bits);
# print "pseudonym bit word:\n" . "$pseudonym_bits\n";
# print "Bit length of pseudonym (should be 138) is: $pseudonym_bit_length\n";
#####

##### Get Tag
$tag = substr($pseudonym_bits,0,6);
# print "Pseudonym Tag: $tag\n";
#####

##### Get Key Indicator
$key_indicator = substr($pseudonym_bits,6,4);
# print "Key Indicator: $key_indicator\n";
#####

##### Get EBC encrypted IMSI
# print "Stripping last 128bits\n";
$encrypted_imsi = substr($pseudonym_bits, -128);
# print "Encrypted IMSI bit word:\n" . "$encrypted_imsi\n";
# print "Length of encrypted IMSI is (should be 128): " . length($encrypted_imsi) . " bits\n";
#####

##### Make IMSI bits into HEX
$encrypted_imsi_hex = pack('B*', $encrypted_imsi);
# print "Length of Encrypted IMSI (HEX): " . length($encrypted_imsi_hex) . "\n";
#####

# print "Using 128bit key: " . $crypt->key . "\n";
# print "Using cipher method: " . $crypt->cipher . "\n";
# print $crypt->padding . "\n";
$crypt->start('encrypt') || die $crypt->errstring;

##### EBC decipher IMSI
$imsi_hex = $crypt->decrypt($encrypted_imsi_hex);
$length_imsi_hex = length($imsi_hex);
# print "Length of deciphered IMSI (HEX): $length_imsi_hex\n";
$imsi_binary = unpack('B*', $imsi_hex);
# print "DECODED BINARY BIT WORD:\n" . "$imsi_binary\n";
####

##### Strip out first 64 bitss
$actual_imsi = substr($imsi_binary,0,64);
# print "Actual IMSI (bit word): $actual_imsi\n";
# print length($actual_imsi) . "\n";
$actual_imsi = substr($imsi_binary,0,64);
# print "Actual IMSI (bit word): $actual_imsi\n";
# print length($actual_imsi) . "\n";

$imsi_hex = pack('B*', $actual_imsi);
$imsi_hex_string = unpack('H*', $imsi_hex);
$imsi_hex_string =~ s/^f//g;
# print "Compressed IMSI:$imsi_hex_string\n";
print "$imsi_hex_string";

exit();


sub base64a2b {
  local @param_array = @_;
  local $param_byte = $param_array[0];

  local $p_count;
  local $return_base64ord = 0;

  for($p_count=0; $p_count < 64; $p_count++) {
    if ($base64[$p_count] eq $param_byte) {
      $return_base64ord = $p_count;
    }
  }

  local $param_bit_string = dec2bin($return_base64ord);
  local $dec2bin_string = $param_bit_string;
  # local $param_bit_string = unpack('B*', $return_base64ord);
  # local $param_return_6bits = substr($param_bit_string,-6);
  local $param_bit_string_length = length($param_bit_string);
  if ($param_bit_string_length < 6) {
    # print "Padding for $param_bit_string [ $param_bit_string_length ]\n";
    local $pad_length = 6 - $param_bit_string_length;
    for($p_count=0; $p_count < $pad_length; $p_count++) {
      $param_bit_string = '0' . $param_bit_string;
    }
  }
  # print "$param_byte $return_base64ord $param_bit_string\n";

  return $param_bit_string;
}

sub dec2bin {
  local $str = unpack("B32", pack("N", shift));
  $str =~ s/^0+(?=\d)//;   # otherwise you'll get leading zeros
  return $str;
}

