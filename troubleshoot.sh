#!/bin/bash
#Written by Brad Johnson - LogRhythm Support
#This script will gather various information about the linux DX and write it out into the $script_dir directory.
#AlMesa
#Variables you may want to change.
user="root"					#$user is the username used for ssh access to the nodes and moving files between nodes.
password=""
script_dir="/tmp/troubleshooting"	#$script_dir is the working directory for the script output.  If you cannot use /tmp change this to another location.

#Setup script variables and environment
option5=false
executed=false
script_exit=false
multinode=false
singlenode=true #set to not run cluster wide stuff as it doesn't work at the moment
mkdir -p $script_dir/{logs,tmp}
chown -R logrhythm.logrhythm $script_dir
timestamp="$(echo -n "dx_diagnostics_";date +%F"_"%H"-"%M)"

#Set color variables
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
WHITE=$(tput setaf 7)
NORMAL=$(tput sgr0)

#DX specific services or log locations.  ***This can change on release, so update as needed.***
log_directories="/var/log/elasticsearch/* /var/log/grafana/* /var/log/influxdb/* /var/log/nginx/* /var/log/persistent/* /var/log/messages"
log_directories_tar="elasticsearch/ grafana/ influxdb/ nginx/ persistent/ messages"
lr_services="$(cat /usr/local/logrhythm/unicon/c/services.yml | grep -Po '(?<=\s-\s).*?$')"
cluster_name="$(cat /etc/elasticsearch/elasticsearch.yml | grep -P 'cluster\.name' | grep -Po '(?<=cluster\.name: ).*?$')"
num_nodes="$(cat /etc/elasticsearch/elasticsearch.yml | grep discovery.zen.ping.unicast.hosts | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | wc -l)"
local_addresses="$(ip addr | grep inet | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | uniq)"

#service_plain function - Same as function below, just for outputting into a Windows format.
#service_function - This function will gather DX service status
service_plain () {
	echo "Data Indexer Service Status:"
	echo
	printf "%-20s  %-14s  %-15s\n" "Service name" "is-Active" "is-Enabled"
	echo "--------------------------------------------------"

	for service in $lr_services; do
		enabled="$(systemctl is-enabled $service)"
		active="$(systemctl is-active $service)"
		printf "%-20s  %-14s  %-15s\n" "$service" "$active" "$enabled"
	done
}

service_function () {
	#DX services information will be printed out in a formatted grid.  Services that are healthy will be in green, with other services having red/yellow depending on status.  Update the $lr_services variable if any other services are to checked.
	if [[ $option5 = false ]]; then
		echo "${YELLOW}Data Indexer Service Status:${NORMAL}"
		echo
		printf "%-20s  %-14s  %-15s\n" "Service name" "is-Active" "is-Enabled"
		echo "--------------------------------------------------"
		for service in $lr_services; do
			enabled="$(systemctl is-enabled $service | sed ''/enabled/s//`printf "${GREEN}enabled${NORMAL}"`/'' | sed ''/disabled/s//`printf "${RED}disabled${NORMAL}"`/'')";
			active="$(systemctl is-active $service |  sed ''/active/s//`printf "${GREEN}active${NORMAL}"`/'' | sed ''/inactive/s//`printf "${RED}inactive${NORMAL}"`/'' | sed ''/unknown/s//`printf "${YELLOW}unknown${NORMAL}"`/'')";
			printf "%-20s  %-25s  %-20s\n" "$service" "$active" "$enabled"
		done
		echo
	elif [[ $option5 = true ]]; then
		echo
		echo "${YELLOW}Grabbing service information...${NORMAL}"
		if [[ $multinode = false ]]; then
			serviceplain=$(service_plain)
			echo "$serviceplain" > $script_dir/dx_services.txt
			echo "${GREEN}Done!${NORMAL}"
		else
			for node in $nodes; do
			    if [[ $node = "$local_node_address" ]]; then
					echo "> ${YELLOW}Node: ${GREEN}Local${NORMAL}"
					serviceplain=$(service_plain)
					echo "$serviceplain" >> $script_dir/dx_services.txt
				else
					echo "> ${YELLOW}Node: ${GREEN}$node${NORMAL}"
				    sshpass -e ssh -tq $user@$node "lr_services=\"$lr_services\"; $(typeset -f); service_plain" >> $script_dir/dx_services.txt
				fi
			done
		fi
	fi
}

#clusterstats_plain - Same as function below, just for outputting into a Windows format.
#clusterstats_function - This function will run curl commands against the DX cluster looking for cluster health and bad shards
clusterstats_plain () {
	echo "Nodes assigned to cluster"
	curl -s 'http://localhost:9200/_cat/nodes?v&h=id,host,disk.avail,heap.current,heap.percent,heap.max'
	echo
	echo "Cluster health"
	curl -s http://localhost:9200/_cluster/health?pretty
	echo
	echo "The current master is"
	curl -s http://localhost:9200/_cat/master
	echo
	echo "The following indices exist on the cluster"
	curl -s http://localhost:9200/_cat/indices?v
	echo
	echo "Cluster wide shard information"
	curl -s http://localhost:9200/_cat/shards
	echo
}

clusterstats_function () {
	if [[ $option5 = false ]]; then
		#curl cluster information into files for use later	
		curl -s http://localhost:9200/_cat/master -o $script_dir/tmp/master.txt
		curl -s http://localhost:9200/_cluster/health?pretty -o $script_dir/tmp/health.txt
		curl -s 'http://localhost:9200/_cat/nodes?v&h=id,host,disk.avail,heap.current,heap.percent,heap.max' -o $script_dir/tmp/nodes.txt
		curl -s http://localhost:9200/_cat/indices?v -o $script_dir/tmp/indices.txt
		curl -s http://localhost:9200/_cat/shards -o $script_dir/tmp/shards.txt
		#Prints out the current master, omitting the first column of the curl as it doesn't make sense from a human readable stance.
		echo
		echo -n "${GREEN}The current master is:${NORMAL}  "
		cat $script_dir/tmp/master.txt | awk '{print $2,$3,$4}'
		echo
		#List node information for the cluster
		echo "${GREEN}Nodes assigned to cluster.${NORMAL}"
		cat $script_dir/tmp/nodes.txt
		echo
		#This line will display cluster health, awk command will loop through output omitting the first and last lines ({} characters)
		#sed arguments will clean up the formatting of the output to a more readable output.
		echo "${GREEN}Current cluster health:${NORMAL}"
		cat $script_dir/tmp/health.txt | awk 'NR>2 {print l} {l=$0}' | sed 's/"//g' | sed 's/,//g' | sed 's/ :/:/g' | sed ''/green/s//`printf "${GREEN}green${NORMAL}"`/'' | sed ''/red/s//`printf "${RED}red${NORMAL}"`/''
		echo
		#This will echo out the indices on the system highlighting status for green or red
		echo "${GREEN}The following indices are present in the $cluster_name cluster:${NORMAL}"
		cat $script_dir/tmp/indices.txt | sed ''/green/s//`printf "${GREEN}green${NORMAL}"`/'' | sed ''/red/s//`printf "${RED}red${NORMAL}"`/'' | sed ''/yellow/s//`printf "${YELLOW}yellow${NORMAL}"`/''
		echo
		#This section will look at the shards cluster wide, might use this instead of previous statement as it could be more useful on multinode clusters.
		echo "${GREEN}Cluster wide shard information:${NORMAL}"
		cat $script_dir/tmp/shards.txt | sed ''/STARTED/s//`printf "${GREEN}STARTED${NORMAL}"`/'' | sed ''/UNASSIGNED/s//`printf "${RED}UNASSIGNED${NORMAL}"`/'' | sed ''/INITIALIZING/s//`printf "${YELLOW}INITIALIZING${NORMAL}"`/''
		echo
	elif [[ $option5 = true ]]; then
		echo
		echo "${YELLOW}Grabbing cluster info from elasticsearch...${NORMAL}"
		clusterplain=$(clusterstats_plain)
		echo "$clusterplain" > $script_dir/cluster_stats.txt
		echo "${GREEN}Done!${NORMAL}"
	fi
}

#sysinfo_plain - Same as function below, just for outputting into a Windows format.
#sysinfo_function - This function will run and grab basic system information such as disk/memory usage, and some hardware info.
sysinfo_plain () {
    echo "Current system time:" 
    date 
    echo -n "System has been "  
    uptime -p 
    echo
    echo -n "Currently logged in:" 
    w | cut -d " " -f 1 - | grep -v USER | sort -u
    echo 
    echo "System information:" 
    echo 
    hostnamectl status | sed -e 's/^[[:space:]]*//' 
    echo 
    echo "Processor info:"
    echo -n "Cores:  " 
    nproc 
    cat /proc/cpuinfo | grep -m 1 "model name"
    lscpu | grep 'CPU MHz'
    echo
    echo "Memory usage:" 
    free -hm 
    echo 
    echo "Disk usage:" 
    df -kh 
    echo
}

sysinfo_function () {
	if [[ $option5 = false ]]; then
        #opening statement declaring current datetime and uptime
        echo "${YELLOW}Current system time:${NORMAL}"
        date
        echo -n "System has been "
        uptime -p
        echo
        #list of currently logged user via w command.
        echo -n "${YELLOW}Currently logged in:${NORMAL}"
        w | cut -d " " -f 1 - | grep -v USER | sort -u
        echo
        #info about the system
        #Grab hostname/OS information
        echo "${YELLOW}Hostname and OS information${NORMAL}"
        hostnamectl status | sed -e 's/^[[:space:]]*//'
        echo
        #Grab number of cores using nproc command, the model of processor from cpuinfo file, and current clock speeds with lscpu
        echo "${YELLOW}Processor info:${NORMAL}"
        echo -n "Cores:  "
        nproc
        cat /proc/cpuinfo | grep -m 1 "model name"
        lscpu | grep 'CPU MHz'
        echo
        #total memory usage listed in MB
        echo "${YELLOW}Memory usage:${NORMAL}"
        free -hm
        echo
        #info about disk usage
        echo "${YELLOW}Disk usage:${NORMAL}"
        df -kh
        echo
    elif [[ $option5 = true ]]; then
    	echo
	    echo "${YELLOW}Grabbing system information...${NORMAL}"
    	if [[ $multinode = false ]]; then
	        sysplain=$(sysinfo_plain)
	        echo "$sysplain" > $script_dir/sysinfo.txt
	        echo "${GREEN}Done!${NORMAL}"
	    else
	    	for node in $nodes; do
		    	if [[ $node = "$local_node_address" ]]; then
			        echo "> ${YELLOW}Node: ${GREEN}Local${NORMAL}"
			        sysplain=$(sysinfo_plain)
			        echo "$sysplain" >> $script_dir/sysinfo.txt
			    else
			        echo "> ${YELLOW}Node: ${GREEN}$node${NORMAL}"
			        sshpass -e ssh -tq -oStrictHostKeyChecking=no $user@$node "$(declare -f); sysinfo_plain" >> $script_dir/sysinfo.txt
			    fi
	    	done
	    fi
    fi
}

#This function will grab the DX logs and the main system log.  
#They will be archived to the $script_dir/logs directory with hostname and timestamp of archive creation.
archiving_function () {
	#This loop will look to see if there is more than one node in a cluster.  If so the user will be prompted to gather logs cluster wide, or only on the local host.  If there is only one node in the cluster, no chocice is given,
	#and the local log files are archived without any interaction.
	echo
	if [[ $multinode = true ]]; then
		echo "Do you want to collect logs from all ${GREEN}$num_nodes nodes${NORMAL} in the ${GREEN}$cluster_name cluster?${NORMAL}"
		select allnodes in "Yes" "No"; do
    	case $allnodes in
        	Yes ) echo; echo "Collecting logs from ${GREEN}$num_nodes nodes${NORMAL} in the ${GREEN}$cluster_name cluster.${NORMAL}"; echo; break;;
        	No ) echo; echo "${GREEN}Only local log files will be collected.${NORMAL}"; echo; singlenode=true; break;;
    	esac
		done
	fi

	#This loop handles the archiving.  If there is only one node in a cluster or user has selected to only gather logs from the local system, log files of interest are copied to $script_dir/logs to be zipped up with the rest of hte files on exit.
	#If Theare is more than one node in the cluster, and  the user selected to grab logs from all nodes, it will use ssh into the other nodes, to zip the log files of interest up to /tmp/dx_logs, and scp them back to the host running the script.
	#All files created on remote hosts will be removed after they have been transferred.  Logs are zipped up remotely in order to limit data transferred across the network.  Local logs handled the same way, just to be consistent in the final output.
	if [[ $multinode = false ]] || [[ $singlenode = true ]]; then
		echo "${YELLOW}Archiving local log files...${NORMAL}"
		tar -czf $script_dir/logs/$HOSTNAME.tar.gz -C /var/log $log_directories_tar 2> /dev/null
		echo "${GREEN}Done!${NORMAL}"
		echo
	elif [[ $multinode = true ]] && [[ $singlenode = false ]]; then
		for node in $nodes; do
			log_timestamp="$(echo -n $node; echo -n "_";date +%F"_"%H"-"%M)"
			if [[ $node = "$local_node_address" ]]; then
				echo
				echo "${YELLOW}Archiving log files on ${GREEN}$node${NORMAL}..."
				tar -czf $script_dir/logs/$log_timestamp.tar.gz -C /var/log $log_directories_tar 2> /dev/null
				echo "${GREEN}Successfully archived log files on ${GREEN}$node${NORMAL}"
				echo
			else
				echo
				echo "${YELLOW}Connecting to node ${GREEN}$node${NORMAL}..."
				sshpass -e ssh -tq -oStrictHostKeyChecking=no $user@$node "if [ ! -d /tmp/dx_logs ]; then mkdir /tmp/dx_logs; fi; echo \"${GREEN}Connected to node $node${NORMAL}\"; echo \"> ${YELLOW}Archiving log files on ${GREEN}$node${NORMAL}...\"; sudo tar -czf /tmp/dx_logs/$log_timestamp.tar.gz -C /var/log $log_directories_tar 2> /dev/null; echo \"> ${GREEN}Done!${NORMAL}\""
				echo "> ${YELLOW}Transferring logs to ${GREEN}$HOSTNAME${NORMAL}..."
				sshpass -e scp -oStrictHostKeyChecking=no $user@$node:/tmp/dx_logs/* $script_dir/logs
				echo "> ${GREEN}Done!${NORMAL}"
				echo "> ${YELLOW}Cleaning up temporary files on node ${GREEN}$node${NORMAL}..."
				sshpass -e ssh -tq -oStrictHostKeyChecking=no $user@$node "rm -rf /tmp/dx_logs"
				echo "> ${GREEN}Done!${NORMAL}"
				echo "${GREEN}Successfully archived log files on ${GREEN}$node${NORMAL}"
				echo
			fi
		done
	fi
	echo
}

#This function will determine number of nodes in the cluster, and set the multinode, nodes, and local_node_address variable appropriately.
#using the ping.unicast.hosts value in the /etc/elasticsearch/elasticsearch.yml file we can quickly determine the IP addresses of the nodes elastic will be expecting.
#If this value is more than 1 we will say this a multi node cluster, allowing some error messages to print if there is an invalid cluster configuration.
#We can then compare the ip of the nodes expected by Elastic, and compare it to the configured IP addresses on the system to determine which IP to use for the node the script is run off of.
nodes_function () {
	#Determines how many nodes are in the cluster, and writes to the console as informational messages.
	if [[ $num_nodes -eq 1 ]]; then
		multinode=false
	elif [[ $num_nodes -eq 2 ]] || [[ $num_nodes -gt 10 ]]; then
		multinode=true
		nodes="$(cat /etc/elasticsearch/elasticsearch.yml | grep discovery.zen.ping.unicast.hosts | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')"
		echo "${RED}***Unsupported number of nodes found in cluster***${NORMAL}"
		echo "${RED}There are $num_nodes in the $cluster_name cluster.  The script can be run on the following nodes:${NORMAL}"
		for current_node in $nodes; do
			echo "$current_node"
		done
		echo
	elif [[ $num_nodes -ge 3 ]]; then
		multinode=true
		nodes="$(cat /etc/elasticsearch/elasticsearch.yml | grep discovery.zen.ping.unicast.hosts | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')"
		echo "${GREEN}There are $num_nodes nodes in the $cluster_name cluster.  The script can be run on the following nodes:${NORMAL}"
		for current_node in $nodes; do
			echo "$current_node"
		done
		echo
	fi

	#Compares all IP addresses on the system, and compares them to the hosts in the Elastic cluster, once it matches it sets the local_node_address variable to this IP address.
	for local in $local_addresses; do
		for node in $nodes; do
			if [[ $local = $node ]]; then
				local_node_address=$local
				echo "${GREEN}Running on node ${NORMAL}$HOSTNAME ${GREEN}using IP of ${NORMAL}$local_node_address"
			fi
		done
	done
}

#This function will prompt the user for the users password, masking the input.  If no input is entered the default LogRhythm password will be used.
password_function () {
	unset password
	prompt="Please enter the password for the user $user: "
	while IFS= read -p "$prompt" -r -s -n 1 char
	do
	    if [[ $char == $'\0' ]]
	    then
	         break
	    fi
	    prompt='*'
	    password+="$char"
	done
	export SSHPASS=$password
}

#This function will be ran as the script exits if selected, removing all files other than the archived outout.
cleanup_function () {
	if [[ $executed = false ]]; then
		rm -rf $script_dir
		echo  "Goodbye!"
	elif [[ $executed = true ]]; then
		echo
		echo "${GREEN}Zipping up script files${NORMAL}..."
		rm -rf $script_dir/tmp
		tar -czvf /tmp/$timestamp.tar.gz -C $script_dir . 2> /dev/null
		echo "${GREEN}Done!${NORMAL}"
		echo
		echo "${GREEN}Script files have been zipped up to ${WHITE}/tmp/$timestamp.gz${NORMAL}"
		echo
		echo "Would you like to delete the non archived files?"

		select purge in "Yes" "No"; do
	    case $purge in
	        Yes ) rm -rf $script_dir; echo "${GREEN}All files generated by the script have been removed."; echo; echo "Exiting...${NORMAL}"; break;;
	        No ) echo "${YELLOW}Issue the following command when done troubleshooting \"rm -rf $script_dir\"${NORMAL}"; echo; break;;
	    esac
		done
	fi
}

#prompt user for which portions of the script they need run.  View options (1-3) will only display information locally to the console.  Option 4 will gather the same information as in steps 1-3, but write it to $script_dir.
clear
#Clearing call to nodes function to bring this back to a single node only script
#nodes_function
echo "Choose an option from below"
while [[ $script_exit = false ]]; do
	echo "---------------------------------------------------------------"
	printf "%-37s %-37s\n" '[1]View DX service information' '[2]View cluster information'
	printf "%-37s %-37s\n" '[3]View system information' '[4]Collect files for support'
	printf "%-37s\n" '[5]exit'
	echo -n "> "
	read menu
	    case $menu in
	        1 ) service_function;;
	        2 ) clusterstats_function;;
	        3 ) sysinfo_function;;
	       	4 ) echo "I'm grabbing it all!"; executed=true; script_exit=true; option5=true; clusterstats_function; service_function; sysinfo_function; archiving_function; cleanup_function;;
	       	#This option has been changed to not call password function due to single node script.  Comment above line out and uncomment below line for multi node script functions.
	       	#4 ) echo "I'm grabbing it all!"; executed=true; script_exit=true; option5=true; password_function; clusterstats_function; service_function; sysinfo_function; archiving_function; cleanup_function;;
	        5 ) cleanup_function; script_exit=true;;
	    esac
done
