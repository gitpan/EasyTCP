package Net::EasyTCP;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $_SERIAL %_COMPRESS_AVAILABLE %_ENCRYPT_AVAILABLE);

use IO::Socket;
use IO::Select;
use Storable qw(nfreeze thaw);

#
# This block's purpose is to:
# . Put the list of available modules in %_COMPRESS_AVAILABLE and %_ENCRYPT_AVAILABLE
#
BEGIN {
	my $version;
	my $hasCBC;
	my @_compress_modules = (
		#
		# MAKE SURE WE DO NOT EVER ASSIGN THE SAME KEY TO MORE THAN ONE MODULE, EVEN OLD ONES NO LONGER IN THE LIST
		#
		# HIGHEST EVER USED: 2
		#
		['1', 'Compress::Zlib'],
		['2', 'Compress::LZF'],
		);
	my @_encrypt_modules = (
		#
		# MAKE SURE WE DO NOT EVER ASSIGN THE SAME KEY TO MORE THAN ONE MODULE, EVEN OLD ONES NO LONGER IN THE LIST
		#
		# HIGHEST EVER USED: B
		#
		['B', 'Crypt::RSA', 0],
		['3', 'Crypt::CBC', 0],
		['A', 'Crypt::Rijndael', 1],
		['9', 'Crypt::RC6', 1],
		['4', 'Crypt::Blowfish', 1],
		['6', 'Crypt::DES_EDE3', 1],
		['5', 'Crypt::DES', 1],
		['2', 'Crypt::CipherSaber', 0],
		);
	$hasCBC = 0;
	$_COMPRESS_AVAILABLE{_order} = [];
	$_ENCRYPT_AVAILABLE{_order} = [];
	# Now we check the compress and encrypt arrays for existing modules
	foreach (@_compress_modules) {
		$@ = undef;
		eval {
			eval ("require $_->[1];") || die "$_->[1] not found\n";
			$version = eval ("\$$_->[1]::VERSION;") || "unknown";
			};
		if (!$@) {
			push (@{$_COMPRESS_AVAILABLE{_order}}, $_->[0]);
			$_COMPRESS_AVAILABLE{$_->[0]}{name} = $_->[1];
			$_COMPRESS_AVAILABLE{$_->[0]}{version} = $version;
			}
		}
	foreach (@_encrypt_modules) {
		$@ = undef;
		eval {
			eval ("require $_->[1];") || die "$_->[1] not found\n";
			$version = eval ("\$$_->[1]::VERSION;") || "unknown";
			};
		if (!$@) {
			if ($_->[1] eq 'Crypt::CBC') {
				$hasCBC = 1;
				}
			elsif (($hasCBC && $_->[2]) || !$_->[2]) {
				push (@{$_ENCRYPT_AVAILABLE{_order}}, $_->[0]);
				$_ENCRYPT_AVAILABLE{$_->[0]}{name} = $_->[1];
				$_ENCRYPT_AVAILABLE{$_->[0]}{cbc} = $_->[2];
				$_ENCRYPT_AVAILABLE{$_->[0]}{version} = $version;
				}
			}
		}
	}

require Exporter;
require AutoLoader;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw();
$VERSION = '0.14';

# Preloaded methods go here.

#
# This generates a global keypair and stores it globally
# Takes the name of a module, returns true or false
#
sub _generateglobalkeypair() {
	my $module = shift || return undef;
	foreach (keys %_ENCRYPT_AVAILABLE) {
		if ($_ ne "_order" && $_ENCRYPT_AVAILABLE{$_}{name} eq $module) {
			($_ENCRYPT_AVAILABLE{$_}{localpublickey}, $_ENCRYPT_AVAILABLE{$_}{localprivatekey}) = ();
			($_ENCRYPT_AVAILABLE{$_}{localpublickey}, $_ENCRYPT_AVAILABLE{$_}{localprivatekey}) = &_genkey($_) or return undef;
			last;
			}
		}
	return 1;
	}

#
# This takes any string and returns it in ascii format
#
sub _bin2asc() {
	my $data = shift;
	$data =~ s/(.)/ '%' . sprintf('%02x',ord($1)) /ges;
	$data = uc($data);
	return $data;
	}

#
# This does the opposite of _bin2asc
#
sub _asc2bin() {
	my $data = shift;
	$data =~ s/\%([0-9A-F]{2})/ sprintf("%c",hex($1)) /ges;
	return $data;
	}

#
# This does very very primitive 2-way encryption
# Takes a string and returns it encrypted, or takes an encrypted string and returns plaintext
#
sub _munge() {
	my $data = shift;
	return $data;
	my $c;
	my $t;
	for (0..length($data)-1) {
		$c = substr($data, $_, 1);
		$t = vec($c, 0, 4);
		vec($c, 0, 4) = vec($c, 1, 4);
		vec($c, 1, 4) = $t;
		substr($data, $_, 1) = $c;
		}
	$data = reverse($data);
	return $data;
	}

#
# This takes a client object and a callback keyword and calls back the associated sub if possible
#
sub _callback() {
	my $client = shift;
	my $type = shift;
	if (!$client->{_negotiating} && $client->{_callbacks}->{$type}) {
		&{$client->{_callbacks}->{$type}}($client);
		}
	}

#
# This takes in an encryption key id and generates a key(pair) and returns it/them according to the type
# of encryption specified
# Returns undef on error
# If there are already a keypair for the specified module stored globally, it will return that instead of
# generating new ones.
#
sub _genkey() {
	my $modulekey = shift;
	my $module = $_ENCRYPT_AVAILABLE{$modulekey}{name};
	my $key1 = undef;
	my $key2 = undef;
	my $temp;
	$@ = undef;
	if ($_ENCRYPT_AVAILABLE{$modulekey}{localpublickey} && $_ENCRYPT_AVAILABLE{$modulekey}{localprivatekey}) {
		$key1 = $_ENCRYPT_AVAILABLE{$modulekey}{localpublickey};
		$key2 = $_ENCRYPT_AVAILABLE{$modulekey}{localprivatekey};
		}
	elsif ($module eq 'Crypt::RSA') {
		$temp = Crypt::RSA->new();
		($key1, $key2) = $temp->keygen (
			Size		=>	512,
			Verbosity	=>	0,
			)
			or $@ = $temp->errstr();
		if ($key1) {
			$key1 = &_bin2asc(nfreeze($key1));
			}
		}
	elsif ($module eq 'Crypt::Rijndael') {
		for (1..32) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	elsif ($module eq 'Crypt::RC6') {
		for (1..32) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	elsif ($module eq 'Crypt::Blowfish') {
		for (1..56) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	elsif ($module eq 'Crypt::DES_EDE3') {
		for (1..24) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	elsif ($module eq 'Crypt::DES') {
		for (1..8) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	elsif ($module eq 'Crypt::CipherSaber') {
		for (1..32) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	else {
		$@ = "Unknown encryption module [$module] modulekey [$modulekey]";
		}
	if (!$key1 || !$key2) {
		$@ = "Could not generate encryption keys. $@";
		}
	return ($key1, $key2);
	}

#
# This takes client object, and a reference to a scalar
# And if it can, compresses scalar, modifying the original, via the specified module in the client object
# Returns true if successful, false if not
#
sub _compress() {
	my $client = shift;
	my $rdata = shift;
	my $modulekey = $client->{_compress} || return undef;
	my $module = $_COMPRESS_AVAILABLE{$modulekey}{name};
	if ($module eq 'Compress::Zlib') {
		$$rdata = Compress::Zlib::compress($$rdata);
		return 1;
		}
	elsif ($module eq 'Compress::LZF') {
		$$rdata = Compress::LZF::compress($$rdata);
		return 1;
		}
	return undef;
	}

#
# This does the opposite of _compress()
#
sub _decompress() {
	my $client = shift;
	my $rdata = shift;
	my $modulekey = $client->{_compress};
	my $module = $_COMPRESS_AVAILABLE{$modulekey}{name};
	if ($module eq 'Compress::Zlib') {
		$$rdata = Compress::Zlib::uncompress($$rdata);
		return 1;
		}
	elsif ($module eq 'Compress::LZF') {
		$$rdata = Compress::LZF::decompress($$rdata);
		return 1;
		}
	return undef;
	}

#
# This takes client object, and a reference to a scalar
# And if it can, encrypts scalar, modifying the original, via the specified module in the client object
# Returns true if successful, false if not
#
sub _encrypt() {
	my $client = shift;
	my $rdata = shift;
	my $modulekey = $client->{_encrypt} || return undef;
	my $module = $_ENCRYPT_AVAILABLE{$modulekey}{name};
	my $cbc = $_ENCRYPT_AVAILABLE{$modulekey}{cbc};
	my $temp;
	my $publickey = $client->{_remotepublickey} || return undef;
	if ($publickey =~ /^(\%[0-9A-F]{2})+$/) {
		$publickey = thaw(&_asc2bin($publickey)) || return undef;
		$client->{_remotepublickey} = $publickey;
		}
	if ($module eq 'Crypt::RSA') {
		$temp = Crypt::RSA->new();
		$$rdata = $temp->encrypt(
			Message		=>	$$rdata,
			Key		=>	$publickey,
			Armour		=>	0,
			)
			or return undef;
		return 1;
		}
	elsif ($module eq 'Crypt::CipherSaber') {
		$temp = Crypt::CipherSaber->new($publickey);
		$$rdata = $temp->encrypt($$rdata);
		return 1;
		}
	elsif ($cbc) {
		$temp = Crypt::CBC->new($publickey, $module);
		$$rdata = $temp->encrypt($$rdata);
		return 1;
		}
	return undef;
	}

#
# Does the opposite of _encrypt();
#
sub _decrypt() {
	my $client = shift;
	my $rdata = shift;
	my $modulekey = $client->{_encrypt} || return undef;
	my $module = $_ENCRYPT_AVAILABLE{$modulekey}{name};
	my $cbc = $_ENCRYPT_AVAILABLE{$modulekey}{cbc};
	my $temp;
	my $privatekey = $client->{_localprivatekey} || return undef;
	if ($module eq 'Crypt::RSA') {
		$temp = Crypt::RSA->new();
		$$rdata = $temp->decrypt(
			Cyphertext		=>	$$rdata,
			Key		=>	$privatekey,
			Armour		=>	0,
			)
			or return undef;
		return 1;
		}
	elsif ($module eq 'Crypt::CipherSaber') {
		$temp = Crypt::CipherSaber->new($privatekey);
		$$rdata = $temp->decrypt($$rdata);
		return 1;
		}
	elsif ($cbc) {
		$temp = Crypt::CBC->new($privatekey, $module);
		$$rdata = $temp->decrypt($$rdata);
		return 1;
		}
	return undef;
	}


#
# Once a new client is connected it calls this to negotiate basics with the server
# This must return true once all negotiations succeed or false if not
#
sub _client_negotiate() {
	my $client = shift;
	my $reply;
	my $timeout = 45;
	my @P;
	my $command;
	my $data;
	my $temp;
	my $temp2;
	my $version;
	my $evl;
	my $starttime = time;
	while ((time-$starttime) < $timeout) {
		$reply = $client->receive($timeout, 1);
		if (!defined $reply) {
			last;
			}
		@P = split(/\x00/, $reply);
		$command = shift (@P);
		$evl = undef;
		$data = undef;
		if (!$command) {
			$@ = "Error negotiating with server. No command received.";
			return undef;
			}
		if ($command eq "PF") {
			$@ = "Server rejected supplied password";
			return undef;
			}
		elsif ($command eq "CVF" && !$client->{_donotcheckversion}) {
			$temp = $_COMPRESS_AVAILABLE{$client->{_compress}}{name};
			$version = $_COMPRESS_AVAILABLE{$client->{_compress}}{version};
			$@ = "Compression version mismatch for $temp : Local version $version remote version $P[0] : Upgrade both to same version or run the server in 'donotcompress' mode";
			return undef;
			}
		elsif ($command eq "EVF" && !$client->{_donotcheckversion}) {
			$temp = $_ENCRYPT_AVAILABLE{$client->{_encrypt}}{name};
			$version = $_ENCRYPT_AVAILABLE{$client->{_encrypt}}{version};
			$@ = "Encryption version mismatch for $temp : Local version $version remote version $P[0] : Upgrade both to same version or run the server in 'donotencrypt' mode";
			return undef;
			}
		elsif ($command eq "EN") {
			$data = "EN";
			$evl = 'return("RETURN1");';
			}
		elsif ($command eq "VE") {
			$client->{_version} = $P[0];
			$data = "VE\x00$VERSION";
			}
		elsif ($command eq "CS") {
			$temp = &_munge($P[0]);
			$temp = &_munge(crypt($client->{_password}, $temp));
			$data = "CP\x00$temp";
			}
		elsif ($command eq "EK") {
			$client->{_remotepublickey} = ($client->{_version} >= 0.07) ? &_munge($P[0]) : $P[0];
			$data = "EK\x00";
			$data .= ($client->{_version} >= 0.07) ? &_munge($client->{_localpublickey}) : $client->{_localpublickey};
			}
		elsif ($command eq "EA") {
			$temp2 = "";
			$version = "";
			if(!$client->{_donotencrypt}) {
				foreach (@P) {
					if ($_ENCRYPT_AVAILABLE{$_}) {
						$temp2 = $_;
						$version = $_ENCRYPT_AVAILABLE{$_}{version};
						last;
						}
					}
				$temp2 ||= "";
				$version ||= "";
				}
			$data = "EU\x00$temp2\x00$version";
			if ($temp2) {
				$evl = '$client->{_encrypt} = $temp2;';
				$evl .= '($client->{_localpublickey},$client->{_localprivatekey}) =';
				$evl .= ' &_genkey($client->{_encrypt}) or ';
				$evl .= ' return("RETURN0"); ';
				}
			}
		elsif ($command eq "CA") {
			$temp2 = "";
			$version = "";
			if(!$client->{_donotcompress}) {
				foreach (@P) {
					if ($_COMPRESS_AVAILABLE{$_}) {
						$temp2 = $_;
						$version = $_COMPRESS_AVAILABLE{$_}{version};
						last;
						}
					}
				$temp2 ||= "";
				$version ||= "";
				}
			$data = "CU\x00$temp2\x00$version";
			if ($temp2) {
				$evl = '$client->{_compress} = $temp2;';
				}
			}
		else {
			$data = "NO";
			}
		if (defined $data && !&_send($client, $data, 0)) {
			$@ = "Error negotiating with server. Could not send : $@";
			return undef;
			}
		#
		# NOW WE SEE IF WE NEED TO EVL ANYTHING
		# IF THE RESULT OF THE EVAL IS "RETURNx" WHERE X IS A NUMBER, WE RETURN
		# OTHERWISE WE KEEP GOING
		#
		if (defined $evl) {
			$evl = eval($evl);
			if ($evl =~ /^RETURN(.+)$/) {
				return (($1) ? $1 : undef);
				}
			}
		}
	$@ = "Client timed out while negotiating with server";
	return undef;
	}

#
# Once the server accepts a new connection, it calls this to negotiate basics with the client
# Unlike _client_negotiate() which does not return until negotiation is over, this sub
# sends 1 command or parses one reply at a time then returns immediately
# Although this is much more complicated, it needs to be done so
# the server does not block when a client is negotiating with it
#
# Expects a client object
#
sub _serverclient_negotiate() {
	my $client = shift;
	my $reply;
	my $temp;
	my @P;
	my $command;
	my $version;

	if (!$client->{_negotiating}) {
		return 1;
		}
	
	$reply = $client->data(1);

	if (!defined $reply) { $reply = "" };

	if (length($reply)) {
		#
		# We're parsing a reply the other end sent us
		#
		@P = split(/\x00/, $reply);
		$command = shift(@P);
		if (!$command) {
			$@ = "Error negotiating. No command received from client : $@";
			return undef;
			}
		$client->{_negotiating_lastevent} = "received";
		if ($command eq "EU") {
			$client->{_encrypt} = $P[0];
			if ($client->{_encrypt}) {
				$version = $_ENCRYPT_AVAILABLE{$P[0]}{version};
				if ($version ne $P[1]) {
					unshift(@{$client->{_negotiating_commands}}, "EVF\x00$version");
					}
				($client->{_localpublickey}, $client->{_localprivatekey}) = &_genkey($client->{_encrypt}) or return undef;
				}
			$temp = "EK\x00";
			$temp .= ($client->{_version} >= 0.07) ? &_munge($client->{_localpublickey}) : $client->{_localpublickey};
			unshift(@{$client->{_negotiating_commands}}, $temp);
			}
		elsif ($command eq "CP") {
			if (&_munge($P[0]) eq crypt($client->{_password}, $client->{_cryptsalt}) ) {
				$client->{_authenticated} = 1;
				}
			else {
				$client->{_authenticated} = 0;
				unshift(@{$client->{_negotiating_commands}}, "PF");
				}
			}
		elsif ($command eq "VE") {
			$client->{_version} = $P[0];
			}
		elsif ($command eq "CU") {
			$client->{_compress} = $P[0];
			if ($client->{_compress}) {
				$version = $_COMPRESS_AVAILABLE{$P[0]}{version};
				if ($version ne $P[1]) {
					unshift(@{$client->{_negotiating_commands}}, "CVF\x00$version");
					}
				}
			}
		elsif ($command eq "EK") {
			$client->{_remotepublickey} = ($client->{_version} >= 0.07) ? &_munge($P[0]) : $P[0];
			}
		elsif ($command eq "EN") {
			if ((defined $client->{_password} && length($client->{_password})) && !$client->{_authenticated}) {
				return undef;
				}
			else {
				$client->{_negotiating} = 0;
				delete $client->{_negotiating_lastevent};
				delete $client->{_negotiating_commands};
				return 1;
				}
			}
		else {
			# received unknown reply. so what..
			}
		}
	elsif ($client->{_negotiating_lastevent} ne "sent") {
		# We're sending a command to the other end, now we have to figure out which one
		&_serverclient_negotiate_sendnext($client);
		}
	return undef;
	}

#
# This is called by _serverclient_negotiate(). It's job is to figure out what's the next command to send
# to the other end and send it.
#
# Expects a client object and a class
#
sub _serverclient_negotiate_sendnext() {
	my $client = shift;
	my $class = $client;
	my $data;
	$class =~ s/=.*//g;

	if (!defined $client->{_negotiating_commands}) {
		# Let's initialize the sequence of commands we send
		$data = "\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n";
		$data .= "-----BEGIN CLEARTEXT WELCOME MESSAGE-----\r\n";
		$data .= "::\r\n";
		$data .= "::  HELLO  ::  $class VERSION $VERSION  ::  SERVER READY  ::\r\n";
		$data .= "::\r\n";
		if ($client->{_welcome}) {
			$data .= "::  $client->{_welcome}\r\n";
			$data .= "::\r\n";
			}
		$data .= "-----END CLEARTEXT WELCOME MESSAGE-----\r\n";
		push (@{$client->{_negotiating_commands}}, $data);
		$data = "VE\x00$VERSION";
		push (@{$client->{_negotiating_commands}}, $data);
		if (!$client->{_donotencrypt}) {
			$data = "EA";
			foreach (@{$_ENCRYPT_AVAILABLE{_order}}) {
				$data .= "\x00$_";
				}
			push (@{$client->{_negotiating_commands}}, $data);
			}
		if (!$client->{_donotcompress}) {
			$data = "CA";
			foreach (@{$_COMPRESS_AVAILABLE{_order}}) {
				$data .= "\x00$_";
				}
			push (@{$client->{_negotiating_commands}}, $data);
			}
		if (defined $client->{_password}) {
			if (!exists $client->{_cryptsalt}) {
				$client->{_cryptsalt} = "";
				for (1..2) {
					$client->{_cryptsalt} .= chr(int(rand(93))+33);
					}
				}
			$data = "CS\x00" . &_munge($client->{_cryptsalt});
			push (@{$client->{_negotiating_commands}}, $data);
			}
		push (@{$client->{_negotiating_commands}}, "EN");
		}

	$data = shift @{$client->{_negotiating_commands}};
	if (!defined $data) {
		return undef;
		}
	if (!&_send($client, $data, 0)) {
		$@ = "Error negotiating with client. Could not send : $@";
		return undef;
		}
	$client->{_negotiating_lastevent} = "sent";
	return 1;
	}

#
# This is called whenever a client (true client or serverclient) receives data without the realdata bit set
# It would parse the data and probably set variables inside the client object
#
sub _parseinternaldata() {
	my $client = shift;
	my $data;
	if ($client->{_mode} eq "serverclient" && $client->{_negotiating}) {
		# The serverclient is still negotiating
		if (&_serverclient_negotiate($client) ) {
			# Negotiation's complete and successful
			&_callback($client, "connect");
			}
		}
	else {
		# It's normal internal data
		$data = $client->data(1);
		}
	}



#
# This takes an integer, packs it as tightly as possible as a binary representation
# and returns the binary value
#
sub _packint() {
	my $int = shift;
	my $bin;
        $bin = pack("N", $int);
        $bin =~ s/^\0+//;
	return $bin;
	}

#
# This does the opposite of _packint. It takes a packed binary produced by _packint and
# returns the integer
#
sub _unpackint() {
	my $bin = shift;
	my $int;
        $int = "\0" x (4-length($bin)) . $bin;
        $int = unpack("N", $int);
	return $int;
	}

#
# This creates a new client object and outgoing connection and returns it as an object
# , or returns undef if unsuccessful
# If special parameter _sock is supplied, it will be taken as an existing connection
# and not outgoing connection will be made
#
sub _new_client() {
	my $class = shift;
	my %para = @_;
	my $sock;
	my $self = {};
	my $temp;
	my $remoteip;
	my $remoteport;
	$class =~ s/=.*//g;
	if (!$para{_sock}) {
		if (!$para{host}) {
			$@ = "Invalid host";
			return undef;
			}
		elsif (!$para{port}) {
			$@ = "Invalid port";
			return undef;
			}
		$sock = new IO::Socket::INET(
			PeerAddr	=>	$para{host},
			PeerPort	=>	$para{port},
			Proto		=>	'tcp',
			Timeout		=>	30,
			);
		$self->{_mode} = "client";
		}
	else {
		$sock = $para{_sock};
		$self->{_mode} = "serverclient";
		$self->{_negotiating} = time;
		$self->{_authenticated} = 0;
		}
	if (!$sock) {
		$@ = "Could not connect to $para{host}:$para{port}: $!";
		return undef;
		}
	$sock->autoflush(1);
	if ($para{_remoteport} && $para{_remoteip}) {
		$self->{_remoteport} = $para{_remoteport};
		$self->{_remoteip} = $para{_remoteip};
		}
	else {
		if (!($temp = getpeername($sock))) {
			$@ = "Error getting peername";
			return undef;
			}
		if (!(($remoteport, $remoteip) = sockaddr_in($temp))) {
			$@ = "Error getting socket address";
			return undef;
			}
		if (!($self->{_remoteip} = inet_ntoa($remoteip))) {
			$@ = "Error determing remote IP";
			return undef;
			}
		$self->{_remoteport} = $remoteport;
		}
	$self->{_sock} = $sock;
	$self->{_password} = $para{password};
	$self->{_donotcompress} = ($para{donotcompress}) ? 1 : 0;
	$self->{_donotencrypt} = ($para{donotencrypt}) ? 1 : 0;
	$self->{_donotcheckversion} = ($para{donotcheckversion}) ? 1 : 0;
	$self->{_data} = [];
	bless ($self, $class);
	if ($self->{_mode} eq "client" && !&_client_negotiate($self)) {
		# Bad server
		$self->close();
		$@ = "Error negotiating with server: $@";
		return undef;
		}
	return $self;
	}

#
# This creates a new listening server object and returns it, or returns undef if unsuccessful
#
# Expects a class
#
sub _new_server() {
	my $class = shift;
	my %para = @_;
	my $sock;
	my $self = {};
	if (!$para{port}) {
		$@ = "Invalid port";
		return undef;
		}
	$sock = new IO::Socket::INET(
		LocalPort	=>	$para{port},
		Proto		=>	'tcp',
		Listen		=>	SOMAXCONN,
		Reuse		=>	1,
		);
	if (!$sock) {
		$@ = "Could not create listening socket on port $para{port}: $!";
		return undef;
		}
	$sock->autoflush(1);
	$self->{_sock} = $sock;
	$self->{_selector} = new IO::Select;
	$self->{_selector}->add($sock);
	$self->{_mode} = "server";
	$self->{_welcome} = $para{welcome};
	$self->{_password} = $para{password};
	$self->{_donotcompress} = ($para{donotcompress}) ? 1 : 0;
	$self->{_donotencrypt} = ($para{donotencrypt}) ? 1 : 0;
	$self->{_clients} = {};
	$self->{_clientip} = {};
	#
	# To avoid key-gen delays while running, let's create global RSA keypairs right now
	#
	if (!$self->{_donotencrypt}) {
		if (!&_generateglobalkeypair('Crypt::RSA')) {
			$@ = "Could not generate global Crypt::RSA keypairs. $@";
			return undef;
			}
		}
	bless($self, $class);
	return $self;
	}

#
# This takes a client object and tries to extract a full packet out of it's received data buffer
# If no valid data found, returns undef
# If data found, it deletes it from the data buffer and pushes it into the data field
# Then returns 1 if the data was real data, or 0 if the data was not real data (internal data)
#
sub _extractdata() {
	my $client = shift;
	my $key = substr($client->{_databuffer}, 0, 2);
	my ($alwayson, $complexstructure, $realdata, $reserved, $encrypted, $compressed, $lenlen);
	my $lendata;
	my $len;
	my $data;
	if (length($key) != 2) {
		return undef;
		}
	$alwayson		=	vec($key, 0, 1);
	$complexstructure	=	vec($key, 1, 1);
	$realdata		=	vec($key, 2, 1);
	$encrypted		=	vec($key, 3, 1);
	$compressed             =       vec($key, 4, 1);
	$reserved               =       vec($key, 5, 1);
	$reserved               =       vec($key, 6, 1);
	$reserved               =       vec($key, 7, 1);
	$lenlen			=	vec($key, 1, 8);
	if (!$alwayson) {
		return undef;
		}
	$len = substr($client->{_databuffer}, 2, $lenlen);
	$lendata = &_unpackint($len);
	if (length($client->{_databuffer}) < (2+$lenlen+$lendata)) {
		return undef;
		}
	$data = substr($client->{_databuffer}, 2+$lenlen, $lendata);
	if (length($data) != $lendata) {
		return undef;
		}
	substr($client->{_databuffer}, 0, 2 + $lenlen + $lendata) = '';
	if ($encrypted) {
		&_decrypt($client, \$data) || return undef;
		}
	if ($compressed) {
		&_decompress($client, \$data) || return undef;
		}
	if ($complexstructure) {
		$data = thaw($data);
		if (!$data) {
			$@ = "Error decompressing complex structure: $!";
			return undef;
			}
		}
	push ( @{$client->{_data}} , $data );
	return ($realdata);
	}

#
# This takes a client object and data, serializes the data if necesary, constructs a proprietary protocol packet
# containing the user's data in it, implements crypto and compression as needed, and sends the packet to the supplied socket
# Returns 1 for success, undef on failure
#
sub _send() {
	my $client = shift;
	my $data = shift;
	my $realdata = shift;
	my $sock = $client->{_sock};
	my $encrypted;
	my $compressed;
	my $lendata;
	my $lenlen;
	my $len;
	my $key;
	my $finaldata;
	my $packet;
	my $packetsize = 4096;
	my $temp;
	my $complexstructure = ref($data);
	if (!$sock) {
		$@ = "Error sending data: Socket handle not supplied";
		return undef;
		}
	elsif (!defined $data) {
		$@ = "Error sending data: Data not supplied";
		return undef;
		}
	if ($complexstructure) {
		$data = nfreeze $data;
		}
	$compressed = ($client->{_donotcompress}) ? 0 : &_compress($client, \$data);
	$encrypted = ($client->{_donotencrypt}) ? 0 : &_encrypt($client, \$data);
	$lendata = length($data);
	$len = &_packint($lendata);
	$lenlen = length($len);
	# Reset the key byte into 0-filled bits
	$key = chr(0) x 2;
	vec($key, 0, 16) = 0;
	# 1 BIT: ALWAYSON :
	vec($key, 0, 1) = 1;
	# 1 BIT: COMPLEXSTRUCTURE :
	vec($key, 1, 1) = ($complexstructure) ? 1 : 0;
	# 1 BIT: REAL DATA:
	vec($key, 2, 1) = (defined $realdata && !$realdata) ? 0 : 1;
	# 1 BIT: ENCRYPTED :
	vec($key, 3, 1) = ($encrypted) ? 1 : 0;
	# 1 BIT: COMPRESSED :
	vec($key, 4, 1) = ($compressed) ? 1 : 0;
	# 1 BIT: RESERVED :
	vec($key, 5, 1) = 0;
	# 1 BIT: RESERVED :
	vec($key, 6, 1) = 0;
	# 1 BIT: RESERVED :
	vec($key, 7, 1) = 0;
	# 8 BITS: LENGTH OF "DATA LENGTH STRING"
	vec($key, 1, 8) = $lenlen;
	# Construct the final data and send it:
	$finaldata = $key . $len . $data;
	$len = length($finaldata);
	$temp = 0;
	while (length($finaldata)) {
		$packet = substr($finaldata, 0, $packetsize);
		substr($finaldata, 0, $packetsize) = '';
		$temp += syswrite($sock, $packet, length($packet));
		}
	if ($temp != $len) {
		$@ = "Error sending data: $!";
		return undef;
		}
	else {
		return 1;
		}
	}


# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Net::EasyTCP - Easily create secure, bandwidth-friendly TCP/IP clients and servers

=head1 FEATURES

=over 4

=item *

One easy module to create both clients and servers

=item *

Object Oriented interface

=item *

Event-based callbacks in server mode

=item *

Internal protocol to take care of all the common transport problems

=item *

Transparent encryption

=item *

Transparent compression

=back

=head1 SYNOPSIS

=over 4

=item SERVER EXAMPLE:

	use Net::EasyTCP;

	$server = new Net::EasyTCP(
		mode            =>      "server",
		port            =>      2345,
		)
		|| die "ERROR CREATING SERVER: $@\n";

	$server->setcallback(
		data            =>      \&gotdata,
		connect         =>      \&connected,
		disconnect	=>	\&disconnected,
		)
		|| die "ERROR SETTING CALLBACKS: $@\n";

	$server->start() || die "ERROR STARTING SERVER: $@\n";

	sub gotdata() {
		my $client = shift;
		my $serial = $client->serial();
		my $data = $client->data();
		print "Client $serial sent me some data, sending it right back to them again\n";
		$client->send($data) || die "ERROR SENDING TO CLIENT: $@\n";
		if ($data eq "QUIT") {
			$client->close() || die "ERROR CLOSING CLIENT: $@\n";
			}
		elsif ($data eq "DIE") {
			$server->stop() || die "ERROR STOPPING SERVER: $@\n";
			}
		}

	sub connected() {
		my $client = shift;
		my $serial = $client->serial();
		print "Client $serial just connected\n";
		}

	sub disconnected() {
		my $client = shift;
		my $serial = $client->serial();
		print "Client $serial just disconnected\n";
		}

=item CLIENT EXAMPLE:

	use Net::EasyTCP;

	$client = new Net::EasyTCP(
		mode            =>      "client",
		host            =>      'localhost',
		port            =>      2345,
		)
		|| die "ERROR CREATING CLIENT: $@\n";

	#Send and receive a simple string
	$client->send("HELLO THERE") || die "ERROR SENDING: $@\n";
	$reply = $client->receive() || die "ERROR RECEIVING: $@\n";

	#Send and receive complex objects/strings/arrays/hashes by reference
	%hash = ("to be or" => "not to be" , "just another" => "perl hacker");
	$client->send(\%hash) || die "ERROR SENDING: $@\n";
	$reply = $client->receive() || die "ERROR RECEIVING: $@\n";
	foreach (keys %{$reply}) {
		print "Received key: $_ = $reply->{$_}\n";
		}

	#Send and receive large binary data
	for (1..4096) {
		for (0..255) {
			$largedata .= chr($_);
			}
		}
	$client->send($largedata) || die "ERROR SENDING: $@\n";
	$reply = $client->receive() || die "ERROR RECEIVING: $@\n";

	$client->close();

=back

=head1 DESCRIPTION

This class allows you to easily create TCP/IP clients and servers and provides an OO interface to manage the connection(s).  This allows you to concentrate on the application rather than on the transport.

You still have to engineer your high-level protocol. For example, if you're writing an SMTP client-server pair, you will have to teach your client to send "HELO" when it connects, and you will have to teach your server what to do once it receives the "HELO" command, and so forth.

What you won't have to do is worry about how the command will get there, about line termination, about binary data, complex-structure serialization, encryption, compression, or about fragmented packets on the received end.  All of these will be taken care of by this class.

=head1 CONSTRUCTOR

=over 4

=item new(%hash)

Constructs and returns a new Net::EasyTCP object.  Such an object behaves in one of two modes (that needs to be supplied to new() on creation time).  You can create either a server object (which accepts connections from several clients) or a client object (which initiates a connection to a server).

new() expects to be passed a hash. The following keys are accepted:

=over 4

=item donotcheckversion

Set to 1 to force a client to continue connecting even if an encryption/compression module version mismatch is detected. (Highly unrecommended, upgrade modules instead)
(Optional and acceptable when mode is "client")

=item donotcompress

Set to 1 to forcefully disable L<compression|COMPRESSION AND ENCRYPTION> even if the appropriate module(s) are found.
(Optional)

=item donotencrypt

Set to 1 to forcefully disable L<encryption|COMPRESSION AND ENCRYPTION> even if the appropriate module(s) are found.
(Optional)

=item host

Must be set to the hostname/IP address to connect to.
(Mandatory when mode is "client")

=item mode

Must be set to either "client" or "server" according to the type of object you want returned.
(Mandatory)

=item password

Defines a password to use for the connection.  When mode is "server" this password will be required from clients before the full connection is accepted .  When mode is "client" this is the password that the server connecting to requires.
(Optional)

=item port

Must be set to the port the client connects to (if mode is "client") or to the port to listen to (if mode is "server"). If you're writing a client+server pair, they must both use the same port number.
(Mandatory)

=item welcome

If someone uses an interactive telnet program to telnet to the server, they will see this welcome message.
(Optional and acceptable only when mode is "server")

=back

=back

=head1 METHODS

B<[C] = Available to objects created as mode "client">

B<[S] = Available to objects created as mode "server">

=over 4

=item addclientip(@array)

B<[S]> Adds an IP address (or IP addresses) to the list of allowed clients to a server.  If this is done, the server will not accept connections from clients not in it's list.

The compliment of this function is deleteclientip() .

=item callback(%hash)

See setcallback()

=item clients()

B<[S]> Returns all the clients currently connected to the server.  If called in array context will return an array of client objects.  If called in scalar context will return the number of clients connected.

=item close()

B<[C]> Instructs a client object to close it's connection with a server.

=item compression()

B<[C]> Returns the name of the module used as the compression module for this connection, undef if no compression occurs.

=item data()

B<[C]> Retrieves the previously-retrieved data associated with a client object.  This method is typically used from inside the callback sub associated with the "data" event, since the callback sub is passed nothing more than a client object.

=item deleteclientip(@array)

B<[S]> Deletes an IP address (or IP addresses) from the list of allowed clients to a server.  The IP address (or IP addresses) supplied will no longer be able to connect to the server.

The compliment of this function is addclientip() .

=item disconnect()

See close()

=item do_one_loop()

B<[S]> Instructs a server object to "do one loop" and return ASAP.  This method needs to be called VERY frequently for a server object to function as expected (either through some sort of loop inside your program if you need to do other things beside serve clients, or via the start() method if your entire program is dedicated to serving clients).  Each one loop will help the server do it's job, including accepting new clients, receiving data from them, firing off the appropriate callbacks etc.

=item encryption()

B<[C]> Returns the name of the module used as the encryption module for this connection, undef if no encryption occurs.

=item mode()

B<[C][S]> Identifies the mode of the object.  Returns either "client" or "server"

=item receive($timeout)

B<[C]> Receives data sent to the client by a server and returns it.  It will block until data is received or until a certain timeout of inactivity (no data transferring) has occurred.

It accepts an optional parameter, a timeout value in seconds.  If none is supplied it will default to 300.

=item remoteip()

B<[C]> Returns the IP address of the host on the other end of the connection.

=item remoteport()

B<[C]> Returns the port of the host on the other end of the connection.

=item running()

B<[S]> Returns true if the server is running (started), false if it is not.

=item send($data)

B<[C]> Sends data to a server.  It can be used on client objects you create with the new() constructor, clients objects returned by the clients() method, or with client objects passed to your callback subs by a running server.

It accepts one parameter, and that is the data to send.  The data can be a simple scalar or a reference to something more complex.

=item serial()

B<[C]> Retrieves the serial number of a client object,  This is a simple integer that allows your callback subs to easily differentiate between different clients.

=item setcallback(%hash)

B<[S]> Tells the server which subroutines to call when specific events happen. For example when a client sends the server data, the server calls the "data" callback sub.

setcallback() expects to be passed a hash. Each key in the hash is the callback type identifier, and the value is a reference to a sub to call once that callback type event occurs.

Valid keys in that hash are:

=over 4

=item connect

Called when a new client connects to the server

=item data

Called when an existing client sends data to the server

=item disconnect

Called when an existing client disconnects

=back

Whenever a callback sub is called, it is passed a single parameter, a CLIENT OBJECT. The callback code may then use any of the methods available to client objects to do whatever it wants to do (Read data sent from the client, reply to the client, close the client connection etc...)


=item socket()

B<[C]> Returns the handle of the socket (actually an L<IO::Socket|IO::Socket> object) associated with the supplied object.  This is useful if you're interested in using L<IO::Select|IO::Select> or select() and want to add a client object's socket handle to the select list.

Note that eventhough there's nothing stopping you from reading and writing directly to the socket handle you retrieve via this method, you should never do this since doing so would definately corrupt the internal protocol and may render your connection useless.  Instead you should use the send() and receive() methods.

=item start()

B<[S]> Starts a server and does NOT return until the server is stopped via the stop() method.  This method is a simple while() wrapper around the do_one_loop() method and should be used if your entire program is dedicated ot being a server, and does not need to do anything else concurrently.

=item stop()

B<[S]> Instructs a running server to stop and returns immediately (does not wait for the server to actually stop, which may be a few seconds later).  To check if the server is still running or not use the running() method.

=back

=head1 COMPRESSION AND ENCRYPTION

Clients and servers written using this class will automatically compress and/or encrypt the transferred data if the appropriate modules are found.

Compression will be automatically enabled if one (or more) of: L<Compress::Zlib|Compress::Zlib> or L<Compress::LZF|Compress::LZF> are installed on both the client and the server.

Encryption will be automatically enabled if one (or more) of: L<Crypt::RSA|Crypt::RSA> or L<Crypt::Rijndael|Crypt::Rijndael>* or L<Crypt::RC6|Crypt::RC6>* or L<Crypt::Blowfish|Crypt::Blowfish>* or L<Crypt::DES_EDE3|Crypt::DES_EDE3>* or L<Crypt::DES|Crypt::DES>* or L<Crypt::CipherSaber|Crypt::CipherSaber> are installed on both the client and the server.

Preference to the compression/encryption method used is determind by availablity checking following the order in which they are presented in the above lists.

Note that during the negotiation upon connection, the server and client will communicate the version of the selected encryption/compression modules.  If a version mismatch is found, the client will report a connection failure stating the reason (module version mismatch).  This behavior was necessary since it was observed that different versions of the same module could produce incompatible output.  If this is encountered, it is strongly recommended you upgrade the module in question to the same version on both ends.  However, if you wish to forcefully connect overlooking a version mismatch (risking instability/random problems/data corruption) you may supply the "donotcheckversion" key to the new() constructor of the client object.

To find out which module(s) have been negotiated for use you can use the compression() and encryption() methods.

* Note that for this class's purposes, L<Crypt::CBC|Crypt::CBC> is a requirement to use any of the encryption modules with a * next to it's name in the above list.  So eventhough you may have these modules installed on both the client and the server, they will not be used unless L<Crypt::CBC|Crypt::CBC> is also installed on both ends.

If the above modules are installed but you want to forcefully disable compression or encryption, supply the "donotcompress" and/or "donotencrypt" keys to the new() constructor.

=head1 RETURN VALUES AND ERRORS

The constructor and all methods return something that evaluates to true when successful, and to false when not successful.

There are a couple of exceptions to the above rule and they are the following methods:

=over 4

=item *

clients()

=item *

data()

=back

The above methods may return something that evaluates to false (such as an empty string, an empty array, or the string "0") eventhough there was no error.  In that case check if the returned value is defined or not, using the defined() Perl function.

If not successful, the variable $@ will contain a description of the error that occurred.

=head1 NOTES

=over 4

=item Incompatability with Net::EasyTCP version 0.01

Version 0.02 and later have had their internal protocol modified to a fairly large degree.  This has made compatability with version 0.01 impossible.  If you're going to use version 0.02 or later (highly recommended), then you will need to make sure that none of the clients/servers are still using version 0.01.

=item Internal Protocol

This class implements a miniature protocol when it sends and receives data between it's clients and servers.  This means that a server created using this class cannot properly communicate with a normal client of any protocol (pop3/smtp/etc..) unless that client was also written using this class.  It also means that a client written with this class will not properly communicate with a different server (telnet/smtp/pop3 server for example, unless that server is implemented using this class also).  This limitation will not change in future releases due to the plethora of advantages the internal protocol gives us.

In other words, if you write a server using this class, write the client using this class also, and vice versa.

=item Delays

This class does not use the fork() method whatsoever.  This means that all it's input/output and multi-socket handling is done via select().

This leads to the following limitation:  When a server calls one of your callback subs, it waits for it to return and therefore cannot do anything else.  If your callback sub takes 5 minutes to return, then the server will not be able to do anything for 5 minutes, such as acknowledge new clients, or process input from other clients.

In other words, make the code in your callbacks' subs' minimal and strive to make it return as fast as possible.

=item Deadlocks

As with any client-server scenario, make sure you engineer how they're going to talk to each other, and the order they're going to talk to each other in, quite carefully.  If both ends of the connection are waiting for the other end to say something, you've got a deadlock.

=back

=head1 AUTHOR

Mina Naguib, <mnaguib@cpan.org>

=head1 SEE ALSO

Perl(1), L<IO::Socket>, L<IO::Select>, L<Compress::Zlib>, L<Compress::LZF>, L<Crypt::RSA>, L<Crypt::CBC>, L<Crypt::Rijndael>, L<Crypt::RC6>, L<Crypt::Blowfish>, L<Crypt::DES_EDE3>, L<Crypt::DES>, L<Crypt::CipherSaber>, defined()

=head1 COPYRIGHT

Copyright (C) 2001-2002 Mina Naguib.  All rights reserved.  Use is subject to the Perl license.

=cut

#
# The main constructor. This calls either _new_client or _new_server depending on the supplied mode
#
sub new() {
	my $class = shift;
	my %para = @_;
	# Let's lowercase all keys in %para
	foreach (keys %para) {
		if ($_ ne lc($_)) {
			$para{lc($_)} = $para{$_};
			delete $para{$_};
			}
		}
	if ($para{mode} =~ /^c/i) {
		return &_new_client($class, %para);
		}
	elsif ($para{mode} =~ /^s/i) {
		return &_new_server($class, %para);
		}
	else {
		$@ = "Supplied mode '$para{mode}' unacceptable. Must be either 'client' or 'server'";
		return undef;
		}
	}

#
# Make callback() a synonim to setcallback()
#

sub callback() {
	return &setcallback(@_);
	}

#
# This sub adds an ip address(es) to the list of valid IPs a server can accept connections
# from.
#
sub addclientip() {
	my $self = shift;
	my @ips = @_;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method setcallback()";
		return undef;
		}
	foreach (@ips) {
		$self->{_clientip}{$_} = 1;
		}
	return 1;
	}


#
# This sub does the opposite of addclient(), it removes an ip address(es) from the list
# of valid IPs a server can accept connections from.
#
sub deleteclientip() {
	my $self = shift;
	my @ips = @_;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method setcallback()";
		return undef;
		}
	foreach (@ips) {
		delete $self->{_clientip}{$_};
		}
	return 1;
	}


# 
#
# This method modifies the _callback_XYZ in a server object. These are the routines
# the server calls when an event (data, connect, disconnect) happens
#
sub setcallback() {
	my $self = shift;
	my %para = @_;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method setcallback()";
		return undef;
		}
	foreach (keys %para) {
		if (!exists $para{$_}) {
			$@ = "Callback $_ $para{$_} does not exist";
			return 0;
			}
		$self->{_callbacks}->{$_} = $para{$_};
		}
	return 1;
	}

#
# This method starts the server and does not return until stop() is called.
# All other behavior is delegated to do_one_loop()
#
sub start() {
	my $self = shift;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method start()";
		return undef;
		}
	$self->{_running} = 1;
	$self->{_requeststop} = 0;
	#
	# Let's loop until we're stopped:
	#
	while (!$self->{_requeststop}) {
		$self->do_one_loop() || return undef;
		}
	#
	# If we reach here the server's been stopped
	#
	$self->{_running} = 0;
	$self->{_requeststop} = 0;
	return 1;
	}

#
# This method does "one loop" of server work and returns ASAP
# It should be called very frequently, either through a while() loop in the program
# or through the start() method
#
# It accepts new clients, accepts data from them, and fires off any callback events as necessary
#
sub do_one_loop() {
	my $self = shift;
	my @ready;
	my $clientsock;
	my $tempdata;
	my $serverclient;
	my $realdata;
	my $result;
	my $negotiatingtimeout = 45;
	my $peername;
	my $remoteport;
	my $remoteip;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method start()";
		return undef;
		}
	$self->{_lastglobalkeygentime} ||= time;
	@ready = $self->{_selector}->can_read(1);
	foreach (@ready) {
		if ($_ == $self->{_sock}) {
			#
			# The SERVER SOCKET is ready for accepting a new client
			#
			$clientsock = $self->{_sock}->accept();
			if (!$clientsock) {
				$@ = "Error while accepting new connection: $!";
				return undef;
				}
			#
			# We get remote IP and port, we'll need them to see if client is allowed or not
			#
			$peername = getpeername($clientsock) or next;
			($remoteport, $remoteip) = sockaddr_in($peername) or next;
			$remoteip = inet_ntoa($remoteip) or next;
			#
			# We create a new client object and
			# We see if client is allowed to connect to us
			#
			if (scalar(keys %{$self->{_clientip}}) && !$self->{_clientip}{$remoteip}) {
				#
				# Client's IP is not allowed to connect to us
				#
				close ($clientsock);
				}
			else {
				#
				# We add it to our SELECTOR pool :
				#
				$self->{_selector}->add($clientsock);
				#
				# We create a new client object:
				#
				$self->{_clients}->{$clientsock} = &_new_client(
					$self,
					"_sock"		=>	$clientsock,
					"_remoteport"	=>	$remoteport,
					"_remoteip"	=>	$remoteip
					);
				#
				# And we make it inherit some stuff from the server :
				#
				$self->{_clients}->{$clientsock}->{_serial} = ++$_SERIAL;
				$self->{_clients}->{$clientsock}->{_donotencrypt} = $self->{_donotencrypt};
				$self->{_clients}->{$clientsock}->{_donotcompress} = $self->{_donotcompress};
				$self->{_clients}->{$clientsock}->{_password} = $self->{_password};
				$self->{_clients}->{$clientsock}->{_callbacks} = $self->{_callbacks};
				$self->{_clients}->{$clientsock}->{_welcome} = $self->{_welcome};
				$self->{_clients}->{$clientsock}->{_selector} = $self->{_selector};
				}
			}
		else {
			#
			# One of the CLIENT sockets are ready
			#
			$result = sysread($_, $tempdata, 4096);
			$serverclient = $self->{_clients}->{$_};
			if (!defined $result) {
				#
				# Error somewhere during reading from that client
				#
				&_callback($serverclient, "disconnect");
				$serverclient->close();
				delete $self->{_clients}->{$_};
				}
			elsif ($result == 0) {
				#
				# Client closed connection
				#
				&_callback($serverclient, "disconnect");
				$serverclient->close();
				delete $self->{_clients}->{$_};
				}
			else {
				#
				# Client sent us some good data (not necessarily a full packet)
				#
				$serverclient->{_databuffer} .= $tempdata;
				while (defined ($realdata = &_extractdata($serverclient)) ) {
					if (!$realdata) {
						# It's internal protocol data
						&_parseinternaldata($serverclient);
						}
					else {
						# We found something and it's real data
						&_callback($serverclient, "data");
						}
					}
				}
			}
		}
	#
	# Now we check on all the serverclients still negotiating and help them finish negotiating
	# or weed out the ones timing out
	#
	foreach (keys %{$self->{_clients}}) {
		$serverclient = $self->{_clients}->{$_};
		if ($serverclient->{_negotiating}) {
			if (&_serverclient_negotiate($serverclient) ) {
				&_callback($serverclient, "connect");
				}
			elsif ((time - $serverclient->{_negotiating}) > $negotiatingtimeout) {
				$serverclient->close();
				delete $self->{_clients}->{$_};
				}
			}
		}
	#
	# Now we re-generate the RSA keys if it's been over an hour
	#
	if (!$self->{_donotencrypt} && ((time-$self->{_lastglobalkeygentime}) >= 3600)) {
		if (!&_generateglobalkeypair('Crypt::RSA')) {
			$@ = "Could not generate global Crypt::RSA keypairs. $@";
			return undef;
			}
		$self->{_lastglobalkeygentime} = time;
		}
	return 1;
	}

#
# This method stops the server and makes it return.
# Note: It doesn't stop the server immediately, it sets a flag
# and the flag should in a few seconds cause the infinite loop in start() method to stop
#
sub stop() {
	my $self = shift;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot call method stop()";
		return undef;
		}
	$self->{_requeststop} = 1;
	return 1;
	}

#
# This method sends data to the socket associated with the object
#
sub send() {
	my $self = shift;
	my $data = shift;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method send()";
		return undef;
		}
	return &_send($self, $data);
	}

#
# This method returns the serial number associated with the object
#
sub serial() {
	my $self = shift;
	if (!$self->{_serial}) {
		$self->{_serial} = ++$_SERIAL;
		}
	return $self->{_serial};
	}

#
# This method returns the already-read data associated with the object
# (typically the code in the callback assigned to callback_data would access this method)
#
sub data() {
	my $self = shift;
	my $returnlatest = shift;
	my $data;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method data()";
		return undef;
		}
	if ($returnlatest) {
		$data = pop ( @{$self->{_data}} );
		}
	else {
		$data = shift ( @{$self->{_data}} );
		}
	return $data;
	}

#
# This method reads data from the socket associated with the object and returns it
# Accepts an optional timeout as a first parameter, otherwise defaults to timeout
# Second parameter is internal and is used to haveit return non-realdata instead of passing it to _parseinternaldata()
# Returns the data if successful, undef if not
#
sub receive() {
	my $self = shift;
	my $timeout = shift || 300;
	my $returninternaldata = shift || 0;
	my $temp;
	my $realdata;
	my $result;
	my $lastactivity = time;
	my $selector;
	my @ready;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method receive()";
		return undef;
		}
	$selector = new IO::Select;
	$selector->add($self->{_sock});
	while ((time - $lastactivity) < $timeout) {
		@ready = $selector->can_read($timeout);
		if (!@ready) {
			if ($! =~ /interrupt/i) {
				next;
				}
			else {
				last;
				}
			}
		$result = sysread($self->{_sock}, $temp, 4096);
		if ($result == 0) {
			# Socket closed
			$@ = "Socket closed when attempted reading";
			return undef;
			}
		elsif (!defined $result) {
			# Error in socket
			$@ = "Error reading from socket: $!";
			return undef;
			}
		else {
			# Read good data
			$lastactivity = time;
			$self->{_databuffer} .= $temp;
			while (1) {
				if (defined($realdata = &_extractdata($self)) ) {
					# We read something
					if ($realdata) {
						# It's real data that belongs to the application
						return $self->data(1);
						}
					elsif ($returninternaldata) {
						# It's internal but we've been instructed to return it
						return $self->data(1);
						}
					else {
						# It's internal data so we parse it
						&_parseinternaldata($self);
						}
					}
				else {
					# There's no (more) data to be extracted
					last;
					}
				}
			}
		}
	$@ = "Timed out waiting to receive data";
	return undef;
	}

#
# This method is a synonym for close()
#
sub disconnect() {
	return &close(@_);
	}

#
# This method closes the socket associated with the object
#
sub close() {
	my $self = shift;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method close()";
		return undef;
		}
	if ($self->{_selector} && $self->{_selector}->exists($self->{_sock})) {
		# If the server selector reads this, let's make it not...
		$self->{_selector}->remove($self->{_sock});
		}
	$self->{_sock}->close();
	$self->{_sock} = undef;
	$self->{_data} = [];
	$self->{_databuffer} = undef;
	return 1;
	}

#
# This method returns true or false, depending on if the server is running or not
#
sub running() {
	my $self = shift;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method running()";
		return undef;
		}
	return $self->{_running};
	}

#
# This replies saying what type of object it's passed
#
sub mode() {
	my $self = shift;
	my $mode = ($self->{_mode} eq "server") ? "server" : "client";
	return $mode;
	}

#
# This method replies saying what type of encryption is used, undef if none
#
sub encryption() {
	my $self = shift;
	my $modulekey = $self->{_encrypt};
	if ($self->{_donotencrypt} || !$modulekey) {
		return undef;
		}
	return $_ENCRYPT_AVAILABLE{$modulekey}{name} || "Unknown module name";
	}


#
# This method replies saying what type of compression is used, undef if none
#
sub compression() {
	my $self = shift;
	my $modulekey = $self->{_compress};
	if ($self->{_donotcompress} || !$modulekey) {
		return undef;
		}
	return $_COMPRESS_AVAILABLE{$modulekey}{name} || "Unknown module name";
	}

#
# This returns the IO::Socket object associated with a connection
#
sub socket() {
	my $self = shift;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method socket()";
		return undef;
		}
	return ($self->{_sock} || undef);
	}

#
# This returns an array of all the clients connected to a server in array context
# or the number of clients in scalar context
# or undef if there are no clients or error
#
sub clients() {
	my $self = shift;
	my @clients;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method clients()";
		return undef;
		}
	foreach ( values %{$self->{_clients}} ) {
		if (!$_->{_negotiating}) {
			push (@clients, $_);
			}
		}
	if (@clients) {
		if (wantarray) {
			return (@clients);
			}
		else {
			return (scalar @clients);
			}
		}
	else {
		return undef;
		}
	}


#
# This takes a client object and returns the IP address of the remote connection
#
sub remoteip() {
	my $self = shift;
	my $temp;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method remoteip()";
		return undef;
		}
	return $self->{_remoteip};
	}

#
# This takes a client object and returns the PORT of the remote connection
#
sub remoteport() {
	my $self = shift;
	my $temp;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method remoteport()";
		return undef;
		}
	return $self->{_remoteport};
	}

