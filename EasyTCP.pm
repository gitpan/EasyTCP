package Net::EasyTCP;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $_SERIAL $_SELECTOR @_COMPRESS_AVAILABLE @_ENCRYPT_AVAILABLE);

use IO::Socket;
use IO::Select;
use Storable qw(nfreeze thaw);

#
# This block's purpose is to:
# . Put the list of available modules in @_COMPRESS_AVAILABLE and @_ENCRYPT_AVAILABLE
#
BEGIN {
	my @_compress_modules = (
		['1', 'Compress::Zlib'],
		['2', 'Compress::LZF'],
		);
	my @_encrypt_modules = (
		['3', 'Crypt::CBC', 0],
		['4', 'Crypt::Blowfish', 1],
		['6', 'Crypt::DES_EDE3', 1],
		['5', 'Crypt::DES', 1],
		['2', 'Crypt::CipherSaber', 0],
		);
	my $hasCBC = 0;
	# Now we check the compress and encrypt arrays for existing modules
	foreach (@_compress_modules) {
		$@ = undef;
		eval {
			eval ("require $_->[1];") || die "$_->[1] not found\n";
			};
		if (!$@) {
			push (@_COMPRESS_AVAILABLE, $_);
			}
		}
	foreach (@_encrypt_modules) {
		$@ = undef;
		eval {
			eval ("require $_->[1];") || die "$_->[1] not found\n";
			};
		if (!$@) {
			if ($_->[1] eq 'Crypt::CBC') {
				$hasCBC = 1;
				}
			elsif (($hasCBC && $_->[2]) || !$_->[2]) {
				push (@_ENCRYPT_AVAILABLE, $_);
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
$VERSION = '0.05';

# Preloaded methods go here.


#
# This takes in an encryption key id and generates a key(pair) and returns it/them according to the type
# of encryption specified
# Returns undef on error
#
sub _genkey() {
	my $methodkey = shift;
	my $method = "";
	my $key1 = undef;
	my $key2 = undef;
	my $temp;
	foreach (@_ENCRYPT_AVAILABLE) {
		if ($methodkey eq $_->[0]) {
			$method = $_->[1];
			last;
			}
		}
	if ($method eq 'Crypt::CipherSaber') {
		for (1..32) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	elsif ($method eq 'Crypt::Blowfish') {
		for (1..56) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	elsif ($method eq 'Crypt::DES_EDE3') {
		for (1..24) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	elsif ($method eq 'Crypt::DES') {
		for (1..8) {
			$key1 .= chr(int(rand(93))+33);
			}
		$key2 = $key1;
		}
	return ($key1, $key2);
	}

#
# This takes client object, and a reference to a scalar
# And if it can, compresses scalar, modifying the original, via the specified method in the client object
# Returns true if successful, false if not
#
sub _compress() {
	my $client = shift;
	my $rdata = shift;
	my $methodkey = $client->{_compress} || "";
	my $method = "";
	foreach (@_COMPRESS_AVAILABLE) {
		if ($methodkey eq $_->[0]) {
			$method = $_->[1];
			last;
			}
		}
	if ($method eq 'Compress::Zlib') {
		$$rdata = Compress::Zlib::compress($$rdata);
		return 1;
		}
	elsif ($method eq 'Compress::LZF') {
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
	my $methodkey = $client->{_compress};
	my $method;
	foreach (@_COMPRESS_AVAILABLE) {
		if ($methodkey eq $_->[0]) {
			$method = $_->[1];
			last;
			}
		}
	if ($method eq 'Compress::Zlib') {
		$$rdata = Compress::Zlib::uncompress($$rdata);
		return 1;
		}
	elsif ($method eq 'Compress::LZF') {
		$$rdata = Compress::LZF::decompress($$rdata);
		return 1;
		}
	return undef;
	}

#
# This takes client object, and a reference to a scalar
# And if it can, encrypts scalar, modifying the original, via the specified method in the client object
# Returns true if successful, false if not
#
sub _encrypt() {
	my $client = shift;
	my $rdata = shift;
	my $methodkey = $client->{_encrypt} || return undef;
	my $method = "";
	my $temp;
	my $publickey = $client->{_remotepublickey} || return undef;
	foreach (@_ENCRYPT_AVAILABLE) {
		if ($methodkey eq $_->[0]) {
			$method = $_->[1];
			last;
			}
		}
	if ($method eq 'Crypt::CipherSaber') {
		$temp = Crypt::CipherSaber->new($publickey);
		$$rdata = $temp->encrypt($$rdata);
		return 1;
		}
	elsif ($method eq 'Crypt::Blowfish') {
		$temp = Crypt::CBC->new($publickey, $method);
		$$rdata = $temp->encrypt($$rdata);
		return 1;
		}
	elsif ($method eq 'Crypt::DES_EDE3') {
		$temp = Crypt::CBC->new($publickey, $method);
		$$rdata = $temp->encrypt($$rdata);
		return 1;
		}
	elsif ($method eq 'Crypt::DES') {
		$temp = Crypt::CBC->new($publickey, $method);
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
	my $methodkey = $client->{_encrypt} || return undef;
	my $method;
	my $temp;
	my $privatekey = $client->{_localprivatekey} || return undef;
	foreach (@_ENCRYPT_AVAILABLE) {
		if ($methodkey eq $_->[0]) {
			$method = $_->[1];
			last;
			}
		}
	if ($method eq 'Crypt::CipherSaber') {
		$temp = Crypt::CipherSaber->new($privatekey);
		$$rdata = $temp->decrypt($$rdata);
		return 1;
		}
	elsif ($method eq 'Crypt::Blowfish') {
		$temp = Crypt::CBC->new($privatekey, $method);
		$$rdata = $temp->decrypt($$rdata);
		return 1;
		}
	elsif ($method eq 'Crypt::DES_EDE3') {
		$temp = Crypt::CBC->new($privatekey, $method);
		$$rdata = $temp->decrypt($$rdata);
		return 1;
		}
	elsif ($method eq 'Crypt::DES') {
		$temp = Crypt::CBC->new($privatekey, $method);
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
	my $timeout = 5;
	my @P;
	my $command;
	my $data;
	my $temp;
	my $temp2;
	my $evl;
	my $starttime = time;
	while ((time-$starttime) < $timeout) {
		$reply = $client->receive($timeout, 1);
		if (!defined $reply) {
			$@ = "Error negotiating (1)";
			return undef;
			}
		@P = split(/\x00/, $reply);
		$command = shift (@P);
		$evl = undef;
		$data = undef;
		if (!$command) {
			$@ = "Error negotiating (2)";
			return undef;
			}
		if ($command eq "EN") {
			$data = "EN";
			$evl = 'last;';
			}
		elsif ($command eq "EK") {
			$client->{_remotepublickey} = $P[0];
			$data = "EK\x00$client->{_localpublickey}";
			}
		elsif ($command eq "EA") {
CN1:			foreach $temp (@P) {
				foreach (@_ENCRYPT_AVAILABLE) {
					if ($temp eq $_->[0]) {
						$temp2 = $_->[0];
						last CN1;
						}
					}
				}
			$data = "EU\x00$temp2";
			$evl = '$client->{_encrypt} = $temp2; ($client->{_localpublickey}, $client->{_localprivatekey}) = &_genkey($client->{_encrypt});';
			}
		elsif ($command eq "CA") {
CN2:			foreach $temp (@P) {
				foreach (@_COMPRESS_AVAILABLE) {
					if ($temp eq $_->[0]) {
						$temp2 = $_->[0];
						last CN2;
						}
					}
				}
			$data = "CU\x00$temp2";
			$evl = '$client->{_compress} = $temp2;';
			}
		else {
			$data = "NO";
			}
		if (defined $data && !&_send($client, $data, 0)) {
			$@ = "Error negotiating (3) : $@";
			return undef;
			}
		if (defined $evl) {
			if ($evl =~ /^last/) {
				last;
				}
			else {
				eval($evl);
				}
			}
		}
	return 1;
	}

#
# Once the server accepts a new connection, it calls this to negotiate basics with the client
# Unlike _client_negotiate() which does not return until negotiation is over, this sub
# sends 1 command or parses one reply at a time then returns immediately
# Although this is much more complicated, it needs to be done so
# the server does not block when a client is negotiating with it
#
sub _serverclient_negotiate() {
	my $client = shift;
	my $reply = shift;
	my $data;
	my @P;
	my $command;

	if (!$client->{_negotiating}) {
		return 1;
		}

	if (defined $reply) {
		# We're parsing a reply the other end sent us
		@P = split(/\x00/, $reply);
		$command = shift(@P);
		if (!$command) {
			$@ = "Error negotiating (3): $@";
			return undef;
			}
		$client->{_negotiating_lastevent} = "received";
		if ($command eq "EU") {
			$client->{_encrypt} = $P[0];
			($client->{_localpublickey}, $client->{_localprivatekey}) = &_genkey($client->{_encrypt});
			unshift(@{$client->{_negotiating_commands}}, "EK\x00$client->{_localpublickey}");
			}
		elsif ($command eq "CU") {
			$client->{_compress} = $P[0];
			}
		elsif ($command eq "EK") {
			$client->{_remotepublickey} = $P[0];
			}
		elsif ($command eq "EN") {
			return 1;
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
sub _serverclient_negotiate_sendnext() {
	my $client = shift;
	my $data;

	if (!defined $client->{_negotiating_commands}) {
		# Let's initialize the sequence of commands we send
		$data = "EA";
		foreach (@_ENCRYPT_AVAILABLE) {
			$data .= "\x00$_->[0]";
			}
		push (@{$client->{_negotiating_commands}}, $data);
		$data = "CA";
		foreach (@_COMPRESS_AVAILABLE) {
			$data .= "\x00$_->[0]";
			}
		push (@{$client->{_negotiating_commands}}, $data);
		push (@{$client->{_negotiating_commands}}, "EN");
		}

	$data = shift @{$client->{_negotiating_commands}};
	if (!defined $data) {
		return undef;
		}
	if (!&_send($client, $data, 0)) {
		$@ = "Error negotiating (1) : $@";
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
	my $data = shift;
	my @P = split(/\x00/, $data);
	my $command = shift(@P) || return undef;;
	my $temp;
	return 1;
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
		$class =~ s/=.*//g;
		$sock = $para{_sock};
		$self->{_mode} = "serverclient";
		}
	if (!$sock) {
		$@ = "Could not connect to $para{host}:$para{port}: $!";
		return undef;
		}
	$sock->autoflush(1);
	$self->{_sock} = $sock;
	$self->{_donotcompress} = ($para{donotcompress}) ? 1 : 0;
	$self->{_donotencrypt} = ($para{donotencrypt}) ? 1 : 0;
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
	$self->{_mode} = "server";
	$self->{_donotcompress} = ($para{donotcompress}) ? 1 : 0;
	$self->{_donotencrypt} = ($para{donotencrypt}) ? 1 : 0;
	bless($self, $class);
	return $self;
	}

#
# This takes a reference to a scalar, extracts a fully qualified data out of it
# if possible, modifies the original scalar to what's left, does decryption and decompression as necessary
# If no valid data found, returns undef
# Otherwise returns the read data and the realdata bit value in a 2-element array if wantarray,
# or just the data if not wantarray
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
	substr($client->{_databuffer}, 0, 2 + $lenlen + $lendata, '');
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
			$data = undef;
			}
		}
	if (wantarray) {
		return ($data, $realdata);
		}
	else {
		return $data;
		}
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
	my $packet;
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
	# Construct the final packet and send it:
	$packet = $key . $len . $data;
	$temp = syswrite($sock, $packet, length($packet));
	if ($temp != length($packet)) {
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

Net::EasyTCP - Easily create TCP/IP clients and servers

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

B<new(%hash)>

Constructs and returns a new Net::EasyTCP object.  Such an object behaves in one of two modes (that needs to be supplied to new() on creation time).  You can create either a server object (which accepts connections from several clients) or a client object (which initiates a connection to a server).

new() expects to be passed a hash. The following keys are accepted:

=over 4

=item mode

Must be set to either "client" or "server" according to the type of object you want returned.
(Mandatory)

=item port

Must be set to the port the client connects to (if mode is "client") or to the port to listen to (if mode is "server"). If you're writing a client+server pair, they must both use the same port number.
(Mandatory)

=item host

Must be set to the hostname/IP address to connect to.
(Mandatory when mode is "client")

=item donotcompress

Set to 1 to forcefully disable L<compression|COMPRESSION AND ENCRYPTION> even if the appropriate module(s) are found.
(Optional)

=item donotencrypt

Set to 1 to forcefully disable L<encryption|COMPRESSION AND ENCRYPTION> even if the appropriate module(s) are found.
(Optional)

=back

=head1 METHODS

B<[C] = Available to objects created as mode "client">

B<[S] = Available to objects created as mode "server">

=over 4

=item callback(%hash)

See setcallback()

=item close()

B<[C]> Instructs a client object to close it's connection with a server.

=item compression()

B<[C]> Returns the name of the module used as the compression module for this connection, undef if no compression occurs.

=item data()

B<[C]> Retrieves the previously-retrieved data associated with a client object.  This method is typically used from inside the callback sub associated with the "data" event, since the callback sub is passed nothing more than a client object.

=item disconnect()

See close()

=item encryption()

B<[C]> Returns the name of the module used as the encryption module for this connection, undef if no encryption occurs.

=item mode()

B<[C][S]> Identifies the mode of the object.  Returns either "client" or "server"

=item receive($timeout)

B<[C]> Receives data sent to the client by a server and returns it.  It will block until data is received or until a certain timeout of inactivity (no data transferring) has occurred.

It accepts an optional parameter, a timeout value in seconds.  If none is supplied it will default to 300.

=item running()

B<[S]> Returns true if the server is running (started), false if it is not.

=item send($data)

B<[C]> Sends data to a server.  It can be used on client objects you create with the new() constructor, or with client objects passed to your callback subs by a running server.

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

B<[S]> Starts a server and does NOT return until the server is stopped via the stop() method.  Once a server is started it will accept new client connections as well as parse incoming data from clients and fire off the appropriate callbacks' subs.

=item stop()

B<[S]> Instructs a running server to stop and returns immediately (does not wait for the server to actually stop, which may be a few seconds later).  To check if the server is still running or not use the running() method.

=back

=head1 COMPRESSION AND ENCRYPTION

Clients and servers written using this class will automatically compress and/or encrypt the transferred data if the appropriate modules are found.

Compression will be automatically enabled if one (or more) of: L<Compress::Zlib|Compress::Zlib> or L<Compress::LZF|Compress::LZF> are installed on both the client and the server.

Encryption will be automatically enabled if one (or more) of: L<Crypt::DES_EDE3|Crypt::DES_EDE3> or L<Crypt::Blowfish|Crypt::Blowfish> or L<Crypt::DES|Crypt::DES> or L<Crypt::CipherSaber|Crypt::CipherSaber> are installed on both the client and the server.

Preference to the compression/encryption method used is determind by availablity checking following the order in which they are presented in the above lists.

To find out which module(s) have been negotiated for use you can use the compression() and encryption() methods.

Note that for this class's purposes, L<Crypt::CBC|Crypt::CBC> is a requirement to use L<Crypt::DES_EDE3|Crypt::DES_EDE3> or L<Crypt::Blowfish|Crypt::Blowfish> or L<Crypt::DES|Crypt::DES>.  So eventhough you may have these modules installed on both the client and the server, they will not be used unless L<Crypt::CBC|Crypt::CBC> is also installed on both ends.

If the above modules are installed but you want to forcefully disable compression or encryption, supply the "donotcompress" and/or "donotencrypt" keys to the new() constructor.

=head1 RETURN VALUES AND ERRORS

The constructor and all methods return something that evaluates to true when successful, and to false when not successful.

The only exception to the above rule is the data() method.  If the data received is an empty string or the string "0" then it will evaluate to false which is probably not what you want.  In that case check that the data you just read is defined.

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

L<IO::Socket>, L<IO::Select>, L<Compress::Zlib>, L<Compress::LZF>, L<Crypt::CBC>, L<Crypt::DES_EDE3>, L<Crypt::Blowfish>, L<Crypt::DES>, L<Crypt::CipherSaber>

=head1 COPYRIGHT

Copyright (C) 2001 Mina Naguib.  All rights reserved.  Use is subject to the Perl license.

=cut

#
# The main constructor. This calls either _new_client or _new_server depending on the supplied mode
#
sub new() {
	my $class = shift;
	my %para = @_;
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
		$self->{"_callback_$_"} = $para{$_};
		}
	return 1;
	}

#
# This method starts the server and does not return
# The server then listens for new connections as well as accepts data from existing connections
# And fires off any necessary callback events when necessary
#
sub start() {
	my $self = shift;
	my @ready;
	my $clientsock;
	my %clientobject;
	my $tempdata;
	my $data;
	my $realdata;
	my $result;
	my $error;
	my $negotiatingtimeout = 10;
	$_SELECTOR = new IO::Select;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method start()";
		return undef;
		}
	$self->{_running} = 1;
	$self->{_requeststop} = 0;
	$_SELECTOR->add($self->{_sock});
MLOOP:	while (!$self->{_requeststop}) {
		@ready = $_SELECTOR->can_read(1);
		foreach (@ready) {
			if ($_ == $self->{_sock}) {
				# The SERVER SOCKET is ready for accepting a new client
				$clientsock = $self->{_sock}->accept();
				if (!$clientsock) {
					$error = "Error while accepting new connection: $!";
					last MLOOP;
					}
				$_SERIAL++;
				$_SELECTOR->add($clientsock);
				$clientobject{$clientsock} = &_new_client($self, "_sock" => $clientsock);
				$clientobject{$clientsock}->{_donotencrypt} = $self->{_donotencrypt};
				$clientobject{$clientsock}->{_donotcompress} = $self->{_donotcompress};
				$clientobject{$clientsock}->{_serial} = $_SERIAL;
				$clientobject{$clientsock}->{_negotiating} = time;
				}
			else {
				# One of the client sockets are ready
				$result = sysread($_, $tempdata, 65536);
				if (!defined $result) {
					# Error somewhere during reading
					if (!$clientobject{$_}->{_negotiating}) {
						&{$self->{_callback_disconnect}}($clientobject{$_}) if ($self->{_callback_disconnect});
						}
					$clientobject{$_}->close();
					delete $clientobject{$_};
					}
				elsif ($result == 0) {
					# Client closed connection
					if (!$clientobject{$_}->{_negotiating}) {
						&{$self->{_callback_disconnect}}($clientobject{$_}) if ($self->{_callback_disconnect});
						}
					$clientobject{$_}->close();
					delete $clientobject{$_};
					}
				else {
					# Client sent us some good data (not necessarily a full packet)
					$clientobject{$_}->{_databuffer} .= $tempdata;
					while (1) {
						($data, $realdata) = &_extractdata($clientobject{$_});
						if (!defined $data) {
							# We found nothing
							last;
							}
						elsif (!$realdata) {
							# We found something, but it's internal protocol data
							if ($clientobject{$_}->{_negotiating}) {
								$result = &_serverclient_negotiate($clientobject{$_}, $data);
								if ($result) {
									$clientobject{$_}->{_negotiating} = 0;
									&{$self->{_callback_connect}}($clientobject{$_}) if ($self->{_callback_connect});
									}
								}
							else {
								&_parseinternaldata($clientobject{$_}, $data);
								}
							}
						else {
							# We found something and it's real data
							$clientobject{$_}->{_data} = $data;
							&{$self->{_callback_data}}($clientobject{$_}) if ($self->{_callback_data});
							}
						}
					}
				}
			}
		# Now we check on all the serverclients still negotiating and help them finish negotiating
		# or weed out the ones timing out
		foreach (keys %clientobject) {
			if ($clientobject{$_}->{_negotiating}) {
				$result = &_serverclient_negotiate($clientobject{$_});
				if ($result) {
					$clientobject{$_}->{_negotiating} = 0;
					&{$self->{_callback_connect}}($clientobject{$_}) if ($self->{_callback_connect});
					}
				elsif ((time-$clientobject{$_}->{_negotiating}) > $negotiatingtimeout) {
					$clientobject{$_}->close();
					delete $clientobject{$_};
					}
				}
			}
		}
	$self->{_running} = 0;
	if ($error) {
		$@ = $error;
		return undef;
		}
	else {
		return 1;
		}
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
	return $self->{_data};
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
	my $data;
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
		$result = sysread($self->{_sock}, $temp, 65536);
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
				($data, $realdata) = &_extractdata($self);
				if (defined $data) {
					# We read something
					if ($realdata) {
						# It's real data that belongs to the application
						return $data;
						}
					elsif ($returninternaldata) {
						# It's internal but we've been instructed to return it
						return $data;
						}
					else {
						# It's internal data so we parse it
						&_parseinternaldata($self, $data);
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
	if ($_SELECTOR && $_SELECTOR->exists($self->{_sock})) {
		# If the server selector reads this, let's make it not...
		$_SELECTOR->remove($self->{_sock});
		}
	$self->{_sock}->close();
	$self->{_sock} = undef;
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
	my $methodkey = $self->{_encrypt};
	if ($self->{_donotencrypt} || !$methodkey) {
		return undef;
		}
	foreach (@_ENCRYPT_AVAILABLE) {
		if ($_->[0] eq $methodkey) {
			return ($_->[1]);
			}
		}
	return undef;
	}


#
# This method replies saying what type of compression is used, undef if none
#
sub compression() {
	my $self = shift;
	my $methodkey = $self->{_compress};
	if ($self->{_donotcompress} || !$methodkey) {
		return undef;
		}
	foreach (@_COMPRESS_AVAILABLE) {
		if ($_->[0] eq $methodkey) {
			return ($_->[1]);
			}
		}
	return undef;
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
