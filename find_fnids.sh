rm -rf obj
mkdir obj
cd obj
for i in $1/*_stub.a; do
  ar x ${i};
done

rm -f FNIDS_temp
for i in *.o* ; do
  FUNC=$(ppu-objdump -D ${i} | sed -e '/\.\.\./d' -e 's/^[ \t]*//' | grep -A1 "^0000000000000000" | grep -B1 "^8" | head -n 1 | cut -b 18- | sed -e 's/^<//g' -e 's/>:$//g')
  FNID=$(ppu-objdump -D ${i} | sed -e '/\.\.\./d' -e 's/^[ \t]*//' | grep -A1 "^0000000000000000" | grep "^8" | cut -b 4-14 | sed -e 's/ //g')
  FNIDS=$(echo "${FUNC}@ 0x${FNID}" | awk -F@ '{print $2"\t"$1}')
  if [ "${FNID}" != "" -a "${FUNC}" != ".psp_libgen_markvar" ]; then
    CPPFUNC=$(ppu-c++filt $(echo "${FUNC}" | sed -e 's/^_Q/_Z/'))
    if [ "${FUNC}" != "${CPPFUNC}" ]; then
      echo "$(echo "${i}" | sed -e 's/^__//g' -e 's/^_//g' | awk -F_ '{print $1"_"$2}' | sed -e 's/_0001//g' -e 's/_$//g')  ${FNIDS} ${CPPFUNC}" | sed -e '/\.toc/d' -e '/[ \t]0x[0-9a-z][ \t]/d' -e '/[ \t]0x[0-9a-z][0-9a-z][ \t]/d' -e '/[ \t]0x[0-9a-z][0-9a-z][0-9a-z][ \t]/d' >> FNIDS_temp
    else
      echo "$(echo "${i}" | sed -e 's/^__//g' -e 's/^_//g' | awk -F_ '{print $1"_"$2}' | sed -e 's/_0001//g' -e 's/_$//g')  ${FNIDS}" | sed -e '/\.toc/d' -e '/[ \t]0x[0-9a-z][ \t]/d' -e '/[ \t]0x[0-9a-z][0-9a-z][ \t]/d' -e '/[ \t]0x[0-9a-z][0-9a-z][0-9a-z][ \t]/d' >> FNIDS_temp
    fi
  fi
  FNIDS=""
  FNID=""
done

cd ..
mv obj/FNIDS_temp .
rm -rf obj

tclsh ps3.tcl > FNIDS_xor
sort FNIDS_xor | uniq > FNIDS_xor2
sort FNIDS_temp | uniq > FNIDS_temp2
rm FNIDS_temp

diff FNIDS_temp2 FNIDS_xor2  | grep -E '^>' | sed -e 's/^> //g' | grep -vE '^Syscall' | grep -vE '^Sysmodule' > FNIDS_temp3
rm FNIDS_xor2

cat FNIDS_temp2 FNIDS_temp3 | sort | uniq > FNIDS
rm FNIDS_temp2
rm FNIDS_temp3

