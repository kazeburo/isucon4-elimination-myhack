package Isu4Qualifier::Model;

use strict;
use warnings;
use utf8;
use DBIx::Sunny;
use Redis::Jet;

sub new {
    bless {}, $_[0];
}

my $users_login_table = +{};
my $users_id_table = {};
{
    my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
    my $port = $ENV{ISU4_DB_PORT} || 3306;
    my $username = $ENV{ISU4_DB_USER} || 'root';
    my $password = $ENV{ISU4_DB_PASSWORD};
    my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';
    my $db = DBIx::Sunny->connect(
        "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
            RaiseError => 1,
            PrintError => 0,
            AutoInactiveDestroy => 1,
            mysql_enable_utf8   => 1,
            mysql_auto_reconnect => 1,
        },
      );
    my $users = $db->select_all( 'SELECT * FROM users' );
    foreach my $u (@$users) {
        $users_login_table->{ $u->{login} } = $u;
        $users_id_table->{ $u->{id} } = $u;
    }
    my $redis = Redis::Jet->new(server => '127.0.0.1:6379',noreply=>1);
    $redis->command('flushall');
    my $log = $db->select_all( 'SELECT * FROM login_log ORDER BY id ASC' );
    foreach my $l (@$log) {
      #ip
      my @pipeline;
      push @pipeline, ['incr',"ip-fail-$l->{ip}"];
      push @pipeline, ['del',"ip-fail-$l->{ip}"] if $l->{succeeded};
      push @pipeline, ['incr',"user-fail-$l->{user_id}"];
      push @pipeline, ['del', "ip-fail-$l->{ip}"] if $l->{succeeded};
      push @pipeline, ['lpush', "user-log-$l->{user_id}", $l->{created_at}."|".$l->{ip}];
      $redis->pipeline(@pipeline);
    }
}


sub user_login {
    $users_login_table->{$_[1]};
}

sub user_id {
    $users_id_table->{$_[1]};
}

sub redis {
  $_[0]->{redis} ||= Redis::Jet->new(server => '127.0.0.1:6379');
}

sub redis_noreply {
  $_[0]->{redis_noreply} ||= Redis::Jet->new(server => '127.0.0.1:6379',noreply=>1);
}

sub last_login {
    my $self = shift;
    my $user_id = shift;
    my $logs = $self->redis->command('lrange',"user-log-$user_id",0,1);
    my $log = $logs->[-1] // '';
    my @log = split /\|/, $log;
    { created_at => $log[0], ip => $log[1] };
}


1;

