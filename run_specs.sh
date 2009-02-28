#!/bin/sh
if [ -x /usr/local/bin/spec19 ]; then
	/usr/local/bin/spec19 firewall_spec.rb --color -fn
else
	/usr/local/bin/spec firewall_spec.rb --color -fn
fi
