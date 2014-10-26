package Isu4Qualifier::Web;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Digest::SHA qw/ sha256_hex /;
use Data::Dumper;
use Redis::Fast;

my $cb = sub {};
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
    my $redis = Redis::Fast->new(server => '127.0.0.1:6379');
    $redis->flushall;
    my $log = $db->select_all( 'SELECT * FROM login_log ORDER BY id ASC' );
    foreach my $l (@$log) {
      #ip
      $redis->incr("ip-fail-$l->{ip}",$cb);
      $redis->del("ip-fail-$l->{ip}",$cb) if $l->{succeeded};
      #user
      $redis->incr("user-fail-$l->{user_id}",$cb);
      $redis->del("user-fail-$l->{user_id}",$cb) if $l->{succeeded};
      #user-log
      $redis->lpush("user-log-$l->{user_id}",$l->{created_at}."|".$l->{ip},$cb) if $l->{succeeded};
      $redis->wait_one_response;
    }
}

sub config {
  my ($self) = @_;
  $self->{_config} ||= {
    user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
    ip_ban_threshold => $ENV{'ISU4_IP_BAN_THRESHOLD'} || 10
  };
};

sub redis {
  $_[0]->{redis} ||= Redis::Fast->new(server => '127.0.0.1:6379',encoding => undef);
}
sub db {
  my ($self) = @_;
  my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
  my $port = $ENV{ISU4_DB_PORT} || 3306;
  my $username = $ENV{ISU4_DB_USER} || 'root';
  my $password = $ENV{ISU4_DB_PASSWORD};
  my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

  $self->{_db} ||= do {
    DBIx::Sunny->connect(
      "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
        RaiseError => 1,
        PrintError => 0,
        AutoInactiveDestroy => 1,
        mysql_enable_utf8   => 1,
        mysql_auto_reconnect => 1,
      },
    );
  };
}

sub calculate_password_hash {
  my ($password, $salt) = @_;
  sha256_hex($password . ':' . $salt);
};

sub attempt_login {
  my ($self, $login, $password, $ip) = @_;
  my $user = $users_login_table->{ $login };

  my ($user_fail,$ip_fail) = $self->redis->mget("user-fail-$user->{id}", "ip-fail-$ip");
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

sub current_user {
  my ($self, $user_id) = @_;
  $users_id_table->{ $user_id };
};

sub last_login {
  my ($self, $user_id) = @_;

  my @logs = $self->redis->lrange("user-log-$user_id",0,1);
  my $log = $logs[-1] // '';
  my @log = split /\|/, $log;
  { created_at => $log[0], ip => $log[1] };
};

sub banned_ips {
  my ($self) = @_;
  my @ips;
  my $threshold = $self->config->{ip_ban_threshold};

  my $not_succeeded = $self->db->select_all('SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?', $threshold);

  foreach my $row (@$not_succeeded) {
    push @ips, $row->{ip};
  }

  my $last_succeeds = $self->db->select_all('SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip');

  foreach my $row (@$last_succeeds) {
    my $count = $self->db->select_one('SELECT COUNT(1) FROM login_log WHERE ip = ? AND ? < id', $row->{ip}, $row->{last_login_id});
    if ($threshold <= $count) {
      push @ips, $row->{ip};
    }
  }

  \@ips;
};

sub locked_users {
  my ($self) = @_;
  my @user_ids;
  my $threshold = $self->config->{user_lock_threshold};

  my $not_succeeded = $self->db->select_all('SELECT user_id, login FROM (SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?', $threshold);

  foreach my $row (@$not_succeeded) {
    push @user_ids, $row->{login};
  }

  my $last_succeeds = $self->db->select_all('SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id');

  foreach my $row (@$last_succeeds) {
    my $count = $self->db->select_one('SELECT COUNT(1) FROM login_log WHERE user_id = ? AND ? < id', $row->{user_id}, $row->{last_login_id});
    if ($threshold <= $count) {
      push @user_ids, $row->{login};
    }
  }

  \@user_ids;
};

sub login_log {
  my ($self, $succeeded, $login, $ip, $user_id) = @_;
  my @lt = localtime;
  my $lt = sprintf('%04d-%02d-%02d %02d:%02d:%02d',$lt[5]+1900,$lt[4]+1,$lt[3],$lt[2],$lt[1],$lt[0]);
  if ( $succeeded ) {
    $self->redis->del("ip-fail-$ip",$cb);
    $self->redis->del("user-fail-$user_id",$cb);
    $self->redis->lpush("user-log-$user_id","$lt|$ip",$cb);
  }
  else {
    $self->redis->incr("ip-fail-$ip",$cb);
    $self->redis->incr("user-fail-$user_id",$cb);
  }
  $self->redis->lpush("login-log", join("\t",$lt,$user_id, $login, $ip, ($succeeded ? 1 : 0)),$cb);
  $self->redis->wait_one_response;
};

sub set_flash {
  my ($self, $c, $msg) = @_;
  $c->req->env->{'psgix.session'}->{flash} = $msg;
};

sub pop_flash {
  my ($self, $c, $msg) = @_;
  delete $c->req->env->{'psgix.session'}->{flash}
    if exists $c->req->env->{'psgix.session'}->{flash};
};

filter 'session' => sub {
  my ($app) = @_;
  sub {
    my ($self, $c) = @_;
    $c->stash->{session_id} = $c->req->env->{'psgix.session.options'}->{id};
    $c->stash->{session}    = $c->req->env->{'psgix.session'};
    $app->($self, $c);
  };
};

get '/' => [qw(session)] => sub {
  my ($self, $c) = @_;

  $c->render('index.tx', { flash => $self->pop_flash($c) });
};

post '/login' => sub {
  my ($self, $c) = @_;
  my $msg;

  my ($user, $err) = $self->attempt_login(
    $c->req->param('login'),
    $c->req->param('password'),
    $c->req->address || '127.0.0.1'
  );

  if ($user && $user->{id}) {
    $c->req->env->{'psgix.session'}->{user_id} = $user->{id};
    $c->redirect('/mypage');
  }
  else {
    if ($err eq 'locked') {
      $self->set_flash($c, 'This account is locked.');
    }
    elsif ($err eq 'banned') {
      $self->set_flash($c, "You're banned.");
    }
    else {
      $self->set_flash($c, 'Wrong username or password');
    }
    $c->redirect('/');
  }
};

get '/mypage' => [qw(session)] => sub {
  my ($self, $c) = @_;
  my $user_id = $c->req->env->{'psgix.session'}->{user_id};
  my $user = $self->current_user($user_id);

  if ($user) {
    $c->render('mypage.tx', { last_login => $self->last_login($user_id) });
  }
  else {
    $self->set_flash($c, "You must be logged in");
    $c->redirect('/');
  }
};

get '/report' => sub {
  my ($self, $c) = @_;
  my @logs = $self->redis->lrange("login-log",0,-1);
  for my $l ( reverse @logs ) {
    my @l = split /\t/, $l;
    $self->db->query(
      'INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) VALUES (?,?,?,?,?)',
      @l
    );
  }

  $c->render_json({
    banned_ips => $self->banned_ips,
    locked_users => $self->locked_users,
  });
};

1;
