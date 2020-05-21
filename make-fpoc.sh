#!/bin/bash
# FortiPoC Cloud Image Preparator
# ranton@fortinet.com
# Version 1.0 - May 2020
# This script doesn't have validation routines for the input values used, so be careful with the information provided.
echo ""
figlet -w 200 Make FortiPoC Image
echo ""
echo "(c) 2020 Fortinet LATAM CSE - Author: ranton@fortinet.com"
echo ""
if [ $# -eq 0 ]; then
	echo "Usage: ./make-fpoc.sh \$fortipoc-1.x.xzip "
else

export GOVC_INSECURE=1
export GOVC_URL="vcsa.fortilabs.org"
export GOVC_USERNAME="administrator@cloud.fortilabs.org"
export GOVC_PASSWORD="Nada123#"
export GOVC_DATASTORE="NVMe01"
export GOVC_NETWORK="VM Network"
export GOVC_RESOURCE_POOL="*/Resources"

	image=$(echo $1|awk -F ".zip" {'print $1'} )

	deploy () {
		echo "[*] Initiating Deployment"
		echo "[*] Procesing FortiPoC image"
		unzip $image
		sed -i "s/please_change/$GOVC_NETWORK/g" $image/fortipoc-8GB.vmx
		ovftool $image/fortipoc-8GB.vmx $image.ova
		govc import.spec $image.ova | python3 -m json.tool > /tmp/$image-temp.json
		sed -i 's/flat/thin/g' /tmp/$image-temp.json
		sed -i "s/\"\"/\"$GOVC_NETWORK\"/g" /tmp/$image-temp.json
		sed -i 's/please_change/eth0/g' /tmp/$image-temp.json
		echo "[*] Deploying OVA to vCenter"
		govc import.ova -name=$image-ga-tpl -options=/tmp/$image-temp.json $image.ova
		echo "[*] OVA deployed"
		echo "[*] Cleaning file"
		rm -rvf $image
		rm -vf $image.ova
		echo "[*] Powering on"
		govc vm.power -on $image-ga-tpl
	}


	check_power () {
		echo "[*] Checking Power status..."
	        check_if_on=$(govc vm.info -json $image-ga-tpl | jq -r '.VirtualMachines[].Runtime.PowerState'|grep -c "poweredOn")
	        if [ "$check_if_on" -gt "0" ]; then
	                counter=0
	                while [ $counter -lt 2 ]; do
	                        check_guest=$(govc vm.info -json $image-ga-tpl |python3 -m json.tool|jq -r .VirtualMachines[].Guest.Net[].Connected 2> /dev/null |grep -c true)
	                        if [ "$check_guest" -ne "0" ]
	                               then
	                                echo "[*] VMWare Tools is up. Still, we will double-check to avoid issues."
	                                let counter=counter+1
	                                sleep 5
	                        else
	                                echo "[*] Still Working..."
        	                        sleep 10
                 	       fi
	                done
		        echo "[*] System Up!"
		else
			govc vm.power -on $image-ga-tpl
			counter=0
			while [ $counter -lt 2 ]; do
				check_guest=$(govc vm.info -json $image-ga-tpl |python3 -m json.tool|jq -r .VirtualMachines[].Guest.Net[].Connected 2> /dev/null |grep -c true)
				if [ "$check_guest" -ne "0" ]
		                       then
		       	                echo "[*] VMWare Tools is up. Still, we will double-check to avoid issues."
		              	        let counter=counter+1
					sleep 5
		                else
		                        echo "[*] Still Working..."
		                       sleep 10
				fi
			done
			echo "[*] System Up!"
		fi
	}

	upgrade () {
		check_power
		sleep 5
		echo "[*] Initiating Upgrade"
		govc vm.ip $image-ga-tpl 1>/dev/null
		fpocip=$(govc vm.info -json=true $image-ga-tpl |jq -r '.VirtualMachines[].Guest.Net[].IpConfig.IpAddress[0].IpAddress' |grep -v null)
		upgrade_version=$(expect -c 'spawn ssh -q -o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/dev/null admin@'$fpocip' exec upgrade; expect "*release\ and\ reboot*"; send "no\r"' | grep -Eo "(\d+\.)+\d+" | grep -v $fpocip)
		current_version=$(curl -s -k  https://$fpocip/login/ | grep '<title>' | grep -Eo "(\d+\.)+\d+")
		sleep 5
		if [ "$current_version" == "$upgrade_version" ]; then
	                echo "[*] FortiPoC already in the latest version"
		else
	                echo "[*] Time to upgrade FortiPoC"
 			expect -c 'spawn ssh -q -o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/dev/null admin@'$fpocip' exec upgrade; expect "*release\ and\ reboot*"; send "yes\r"; interact'
			check_power
			govc vm.ip $image-ga-tpl 1>/dev/null
			sleep 5
	                curl -s -k  https://$fpocip/login/ | grep '<title>' | grep -Eo "(\d+\.)+\d+" > /tmp/new_version
			govc vm.power -off $image-ga-tpl
			sleep 30
		fi

	}

	check_off () {
		echo "[*] Initiate powering off"
		counter=0
		while [ $counter -lt 1 ]; do
			check_guest=$(govc vm.info -json $image-ga-tpl |python3 -m json.tool|jq -r .VirtualMachines[].Runtime.PowerState 2> /dev/null |grep -c poweredOff)
			if [ "$check_guest" -ne "0" ]
       	                        then
                       	                echo "[*] VM is off"
                               	        let counter=counter+1
                                else
                                        govc vm.power -off $image-ga-tpl
					sleep 30
			fi
		done

	}

	create_images () {
		echo "[*] Time to create images"
		timestamp=$(date "+%Y%m%d%H%M")
		new_build=$(cat /tmp/new_version)
		echo "[*] Exporting FortiPoC VM to OVA"
		govc vm.change -vm $image-ga-tpl -name fortipoc-$new_build
		govc export.ovf -sha=1 -vm fortipoc-$new_build .
		echo "[*] Creating KVM image compatible with GCP"
		qemu-img convert -f vmdk -O raw fortipoc-$new_build/fortipoc-$new_build-*.vmdk disk.raw
		tar cf - disk.raw  | pigz -9  > fortipoc-$new_build-$timestamp.tar.gz
		echo "[*] Creating new OVA"
		ovftool -dm=thin fortipoc-$new_build/fortipoc-$new_build.ovf fortipoc-$new_build-$timestamp.ova
		echo "[*] Converting VM to Template"
		govc vm.markastemplate fortipoc-$new_build
		echo "[*] Cleaning files"
		rm -rvf fortipoc-$new_build
		rm -vf disk.raw
		chmod 666 fortipoc-$new_build-*
		echo "[*] vSphere Template: fortipoc-$new_build"
		echo "[*] VMware OVA Image: fortipoc-$new_build-$timestamp.ova"
		echo "[*] KVM Image: fortipoc-$new_build-$timestamp.tar.gz"
	}


	find_vm=$(govc vm.info -r $image-ga-tpl | grep -c Name)

	if [ "$find_vm" -ne "0" ]; then
                echo "[*] Previous template found, executing upgrade"
		upgrade
		check_off
		create_images
	else
                echo "[*] Deploying FortiPoC template"
		deploy
		upgrade
		check_off
		create_images
	fi

fi
