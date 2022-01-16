#!/usr/bin/env perl

use strict;
use warnings;

open my $fh, "<", "main.go" || die $!;

my $version;
while (<$fh>) {
  # CurrentVersion: "v0.04"
  $version = $1 if /CurrentVersion\s*=\s*"([\d\.]+)"/;
}
close $fh;

die "no version?" unless defined $version;

# quit if tests fail
system("go test ./...") && die "not building release with failing tests";

# so lazy
system "rm", "-rf", "release", "dist";
system "mkdir", "release";
system "mkdir", "dist";

my %build = (
  win   => { env => { GOOS => 'windows', GOARCH => 'amd64' }, filename => 'netgiv.exe' },
  linux => { env => { GOOS => 'linux',   GOARCH => 'amd64' }, filename => 'netgiv' },
  mac   => { env => { GOOS => 'darwin',  GOARCH => 'amd64' }, filename => 'netgiv' },
); 

foreach my $type (keys %build) {
  mkdir "release/$type";
}

foreach my $type (keys %build) {
  local $ENV{GOOS}   = $build{$type}->{env}->{GOOS};
  local $ENV{GOARCH} = $build{$type}->{env}->{GOARCH};
  system "go", "build", "-o", "release/$type/" . $build{$type}->{filename};
  system "zip", "-j", "dist/netgiv-$type-$version.zip", ( glob "release/$type/*" );
}
