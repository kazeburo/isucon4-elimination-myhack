use FindBin;
use lib "$FindBin::Bin/extlib/lib/perl5";
use lib "$FindBin::Bin/lib";
use File::Basename;
use Plack::Builder;
use Isu4Qualifier::Web;
use Plack::Session::State::Cookie;
use Plack::Session::Store::File;
use Cache::Memcached::Fast;
use Sereal;
use File::Temp qw/tempdir/;
use Cache::FastMmap;

my $root_dir = File::Basename::dirname(__FILE__);
my $session_dir = "/tmp/isu4_session_plack";
mkdir $session_dir;

my $decoder = Sereal::Decoder->new();
my $encoder = Sereal::Encoder->new();
local $Kossy::XSLATE_CACHE = 2;
local $Kossy::XSLATE_CACHE_DIR = tempdir(DIR=>"/dev/shm");
local $Kossy::SECURITY_HEADER = 0;
my $cfm = Cache::FastMmap->new(raw_values => 1,share_file=>"/dev/shm/sharefile-$$");
my $app = Isu4Qualifier::Web->psgi($root_dir);
builder {
  enable 'ReverseProxy';
  enable 'Session::Simple',
        store => Cache::Memcached::Fast->new({
            servers => [ { address => "localhost:11211",noreply=>0} ],
            serialize_methods => [ sub { $encoder->encode($_[0])}, 
                                   sub { $decoder->decode($_[0])} ],
        }),
      #store => $cfm,
      #serializer => [sub { $encoder->encode($_[0]) }, sub { $decoder->decode($_[0]) }],
      httponly => 1,
      cookie_name => "isu4_session",
      keep_empty => 0;
  $app;
};
