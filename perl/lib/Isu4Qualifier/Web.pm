package Isu4Qualifier::Web;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Redis::Jet;
use Isu4Qualifier::Template;
use Isu4Qualifier::Model;
use List::MoreUtils qw/natatime/;

sub config {
    $_[0]->model->config
};

sub redis {
    $_[0]->model->redis
}

sub redis_noreply {
    $_[0]->model->redis_noreply
}

sub model {
    $_[0]->{mode} ||= Isu4Qualifier::Model->new();
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
    my $flash = $self->pop_flash($c);
    $c->res->body([
        Isu4Qualifier::Template->get('base_before'),
        Isu4Qualifier::Template->get('index_before'),
        $flash ? q!<div id="notice-message" class="alert alert-danger" role="alert">!.$flash.q!</div>! : (),
        Isu4Qualifier::Template->get('index_after'),
        Isu4Qualifier::Template->get('base_after')
        ]);
    $c->res;
};

post '/login' => sub {
  my ($self, $c) = @_;
  my $msg;

  my ($user, $err) = $self->model->attempt_login(
    $c->req->body_parameters_raw->{login},
    $c->req->body_parameters_raw->{password},
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
    my $user = $self->model->user_id($user_id);
    
    if ($user) {
        my $last_login = $self->model->last_login($user_id);
        $c->res->body([
            Isu4Qualifier::Template->get('base_before'),
            Isu4Qualifier::Template->get('mypage_1'),
            $last_login->{created_at},
            Isu4Qualifier::Template->get('mypage_2'),
            $last_login->{ip},
            Isu4Qualifier::Template->get('mypage_3'),
            $user->{login},
            Isu4Qualifier::Template->get('mypage_4'),
            Isu4Qualifier::Template->get('base_after')
            ]);
        $c->res;
    }
    else {
        $self->set_flash($c, "You must be logged in");
        $c->redirect('/');
    }
};

get '/report' => sub {
  my ($self, $c) = @_;
  my $logs = $self->redis->command('lrange',"login-log",0,-1);
  my $it = natatime 600, reverse @$logs;
  while (my @logs = $it->()) {
      my $values = '(?,?,?,?,?),'x(scalar @logs);
      chop $values;
      my @bind;
      push(@bind, split /\t/, $_) for @logs;
      $self->db->query(
          'INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) VALUES '.$values,
          @bind
      );
  }

  $c->render_json({
    banned_ips => $self->banned_ips,
    locked_users => $self->locked_users,
  });
};

1;
