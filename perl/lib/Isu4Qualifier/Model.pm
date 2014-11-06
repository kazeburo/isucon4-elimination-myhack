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

sub config {
  my ($self) = @_;
  $self->{_config} ||= {
    user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
    ip_ban_threshold => $ENV{'ISU4_IP_BAN_THRESHOLD'} || 10
  };
};

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

sub calculate_password_hash {
  my ($password, $salt) = @_;
  sha256_hex($password . ':' . $salt);
};

sub attempt_login {
  my ($self, $login, $password, $ip) = @_;
  my $user = $self->user_login($login);

  my $fail = $self->redis->command('mget',"user-fail-$user->{id}", "ip-fail-$ip");
  my $user_fail = $fail->[0];
  my $ip_fail = $fail->[1];
  if ($self->config->{ip_ban_threshold} <= ($ip_fail // 0)) {
    $self->login_log(0, $login, $ip, $user ? $user->{id} : undef);
    return undef, 'banned';
  }

  if ($self->config->{user_lock_threshold} <= ($user_fail // 0)) {
    $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'locked';
  }

  if ($user && calculate_password_hash($password, $user->{salt}) eq $user->{password_hash}) {
    $self->login_log(1, $login, $ip, $user->{id});
    return $user, undef;
  }
  elsif ($user) {
    $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'wrong_password';
  }
  else {
    $self->login_log(0, $login, $ip);
    return undef, 'wrong_login';
  }
};

sub login_log {
  my ($self, $succeeded, $login, $ip, $user_id) = @_;
  my @lt = localtime;
  my $lt = sprintf('%04d-%02d-%02d %02d:%02d:%02d',$lt[5]+1900,$lt[4]+1,$lt[3],$lt[2],$lt[1],$lt[0]);
  my @pipeline;
  if ( $succeeded ) {
    push @pipeline, ['del',"ip-fail-$ip"], ['del',"user-fail-$user_id"], ['lpush',"user-log-$user_id","$lt|$ip"];
  }
  else {
    push @pipeline, ['incr',"ip-fail-$ip"],['incr',"user-fail-$user_id"];
  }
   push @pipeline, ['lpush',"login-log", join("\t",$lt,$user_id, $login, $ip, ($succeeded ? 1 : 0))];
  $self->redis_noreply->pipeline(@pipeline);
};

1;

