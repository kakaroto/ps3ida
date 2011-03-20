#!/usr/bin/tclsh

set fd [open FNIDS]
set data [read $fd]
close $fd

foreach line [split $data "\n"] {
	set fnid [lindex $line 1]
	set fnids($fnid) $line
} 


puts {/*
 * fnids.h -- FNID to Function Name association per module
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include <idc.idc>
}


set i 0
set prev_module ""

puts "static get_fnid_name(module, fnid) \{"

foreach line [split $data "\n"] {
	if {[string trim $line] == ""} continue
	set module [lindex $line 0]
	set fnid [lindex $line 1]
	set name [lindex $line 2]
	if {[info exists fnids($fnid)] } continue
	if {$module != $prev_module} {
		if {$i > 0} {
			puts "    \} else { return form (\"%X\", fnid); }"
		}
		if {$prev_module == ""} {
			puts "  if (module == \"$module\") \{"
		} else {
			puts "  \} else if (module == \"$module\") \{"
		}
		set prev_module $module
		set i 0
	}
	if {$i == 0} {
		puts "    if (fnid == $fnid) \{"
	} else {
		puts "    \} else if (fnid == $fnid) \{"
	}
	puts "      return \"$name\";"
	incr i
} 

if {$i > 0} {
	puts "    \} else { return form (\"%X\", fnid); }"
}
puts "  \} else \{"
puts "    return form (\"%X\", fnid);"
puts "  \}"
puts "\}\n\n"


set i 0
set prev_module ""

puts "static get_fnid_comment(module, fnid) \{"
foreach line [split $data "\n"] {
	if {[llength $line] != 4} continue
	set module [lindex $line 0]
	set fnid [lindex $line 1]
	set name [lindex $line 3]
	if {[info exists fnids($fnid)] } continue
	if {$module != $prev_module} {
		if {$i > 0} {
			puts "    \} else { return form (\"%X\", fnid); }"
		}
		if {$prev_module == ""} {
			puts "  if (module == \"$module\") \{"
		} else {
			puts "  \} else if (module == \"$module\") \{"
		}
		set prev_module $module
		set i 0
	}
	if {$i == 0} {
		puts "    if (fnid == $fnid) \{"
	} else {
		puts "    \} else if (fnid == $fnid) \{"
	}
	puts "      return \"$name\";"
	incr i
} 

if {$i > 0} {
	puts "    \} else { return \"\"; }"
}
puts "  \} else \{"
puts "    return \"\";"
puts "  \}"
puts "\}\n\n"