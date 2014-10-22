#!/usr/bin/env perl

use strict;
use warnings;

use DBIx::Sunny;
use Redis::Fast;

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
    my $redis = Redis::Fast->new(server => '127.0.0.1:6379');
    $redis->flushall;
    my $log = $db->select_all( 'SELECT * FROM login_log ORDER BY id ASC' );
    foreach my $l (@$log) {
      #ip
      $redis->incr("ip-fail-$l->{ip}",sub{});
      $redis->del("ip-fail-$l->{ip}",sub{}) if $l->{succeeded};
      #user
      $redis->incr("user-fail-$l->{user_id}",sub{});
      $redis->del("user-fail-$l->{user_id}",sub{}) if $l->{succeeded};
      #user-log
      $redis->lpush("user-log-$l->{user_id}",$l->{created_at}."|".$l->{ip},sub{}) if $l->{succeeded};
      $redis->wait_all_responses;
    }
}

