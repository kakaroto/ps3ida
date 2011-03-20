#!/usr/bin/tclsh

source xml.tcl

set xml [::xml::LoadFile ps3.xml]
set i 0
while { true } {
	set node [::xml::GetNode $xml "IdaInfoDatabase:Group" $i]
	if {$node == ""} { break }
	set module [::xml::GetAttribute $node "Group" "name"]
	incr i
	set j 0
	while { true } {
		set group [::xml::GetNode $node "Group:Entry" $j]
		if {$group == ""} {
			break
		}
		set fnid [::xml::GetAttribute $group "Entry" "id"]
		set fnid [string tolower $fnid]
		set name [::xml::GetAttribute $group "Entry" "name"]
		set cppname [exec ppu-c++filt $name]
		if {$name == $cppname} {
			puts "$module   $fnid\t$name"
		} else {
			puts "$module   $fnid\t$name $cppname"
		}
		
		incr j
	}
}
