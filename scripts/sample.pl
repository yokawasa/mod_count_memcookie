#! /usr/bin/perl

use strict;

print "Content-type: text/plain; charset=EUC-JP\n\n";
print "<html>\n";
print "<head><title>ENV CHECKER</title></head>\n";
print "<body>\n";
printf "count->\%s<br>\n", $ENV{ "count_memcookie" };
print "</body>\n";
print "</html>\n";


__END__
