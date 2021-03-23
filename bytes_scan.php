<?php

	$ethertype = [
		"0800" => "IPv4",
		"0806" => "ARP",
		"86dd" => "IPv6"
	];
	$protocols = [
		"01" => "ICMP",
		"06" => "TCP",
		"17" => "UDP",
		"1b" => "RDP",
		"29" => "IPv6",
		"38" => "TLSP"
	];

	function parse_mac($mac){
		return implode(":", str_split($mac, 2)); //insert a colon at each 2 bytes
	}

	function parse_ip($hex){
		$hex = str_split($hex, 2); //splits into octets
		$ip = "";
		foreach($hex as $oct){
			$ip .= hexdec($oct).".";
		}
		return substr($ip,0,-1); //remove the last dot
	}

	function parse_bytes($bytes){
		global $ethertype, $protocols;
		$IP_Payload = "";
		$ethernet["Destination"] = parse_mac(substr($bytes,0,2*6));
		$ethernet["Source"] = parse_mac(substr($bytes,2*6,2*6));
		$ethernet["Type"] = substr($bytes, 2*12,2*2);
		// ." (".$ethertype[substr($bytes, 2*12,2*2)].")";

		switch($ethernet["Type"]){
			case "0800": //IPv4
				$ip["version"] = substr($bytes, 2*14,1);
				$ip["IHL"] = substr($bytes, 29,1); //IHL*4 = end of IP header
				$ip["TypeOfService"] = substr($bytes, 2*15, 2);
				$ip["TotalLength"] = substr($bytes, 2*16, 4);
				$ip["Identification"] = substr($bytes, 2*18, 2*2);
				$ip["Flags"] = substr($bytes, 2*20, 2*1);
				$ip["FragOffset"] = substr($bytes, 2*21, 2*1);
				$ip["TTL"] = substr($bytes, 2*22, 2*1);
				$ip["Protocol"] = substr($bytes, 2*23, 2*1); // 6=tcp;17=udp
					$protocol = $protocols[$ip["Protocol"]];
				$ip["HeadChksum"] = substr($bytes, 2*24, 2*2);
				$ip["SourceAddr"] = parse_ip(substr($bytes, 2*26,2*4));
				$ip["DestAddr"] = parse_ip(substr($bytes, 2*30, 2*4));
				$IP_Payload = "68"; // 2*30 + 2*4

				if($ip["IHL"] > 5){
					$ip["Options"] = substr(2*34, 2*4);
					$IP_Payload = "76"; // 2*34 + 2*4
				}
				break;

			case "86dd": //IPv6
				$ip["version"] = substr($bytes, 2*14,1);
				$ip["TrafficClass"] = substr($bytes, 2*14,2*4);
				$ip["PayloadLength"] = substr($bytes, 2*18,2*2);
				$ip["NextHeader"] = substr($bytes, 2*20,2*1); // ~Protocol (6=tcp;17=udp)
					$protocol = $protocols[$ip["NextHeader"]];

				$ip["HopLimit"] = substr($bytes, 2*21,2*1,);
				$ip["SourceAddr"] = substr($bytes, 2*22,2*16);
				$ip["DestAddr"] = substr($bytes, 2*38,2*16);
				$IP_Payload = "108"; // 2*38 + 2*16
				break;

			case "0806": //ARP
				$arp["HardType"] = substr($bytes,2*14,2*2);
				$arp["ProtoType"] = substr($bytes,2*16,2*2);
				$arp["HardSize"] = substr($bytes,2*18,2*1);
				$arp["ProtoSize"] = substr($bytes,2*19,2*1);
				$arp["Opcode"] = substr($bytes,2*20,2*2);
				$arp["SenderMAC"] = parse_mac(substr($bytes,2*22,2*6));
				$arp["SenderIP"] = parse_ip(substr($bytes,2*28,2*4));
				$arp["TargetMAC"] = parse_mac(substr($bytes,2*32,2*6));
				$arp["TargetIP"] = parse_ip(substr($bytes,2*38,2*4));
				return [$ethernet, $arp];
				break;
		}

		if($protocol == "TCP"){
			$tcp["SourcePort"] = substr($bytes, $IP_Payload,2*2);
			$tcp["DestPort"] = substr($bytes, $IP_Payload+2*2,2*2);
			$tcp["SeqNumber"] = substr($bytes, $IP_Payload+2*4,2*4);
			$tcp["AckNumber"] = substr($bytes, $IP_Payload+2*8, 2*4);
			if($ip["version"] == 4){
				$tcp["DataOffset"] = substr($bytes, $IP_Payload+2*12,1); // 4*DataOffset = len(TCPHeader)
			}
			if($ip["version"] == 6){
				$tcp["DataOffset"] = substr($bytes, $IP_Payload+2*12,2); // 4*DataOffset = len(TCPHeader)
			}
			$tcp["Flags"] = substr($bytes, $IP_Payload+2*13,2*1);
			$tcp["Window"] = substr($bytes, $IP_Payload+2*14,2*2);
			$tcp["Checksum"] = substr($bytes, $IP_Payload+2*16,2*2);
			$tcp["UrgPoint"] = substr($bytes, $IP_Payload+2*18,2*2);
			//len(Options) = len(TCPHeader) - position(UrgPoint)
		//	echo implode(" ",str_split(substr($bytes, $IP_Payload+2*20, $tcp["DataOffset"]*4),2));

			return [
				"Ethernet"=>$ethernet,
				"IP"=>$ip,
				"TCP"=>$tcp
			];
		}
		if($protocol == "UDP"){

			return;
		}
	}

	$file = "bytes_aula.txt";
	//$file = "bytes_ipv6";
//	$file = "bytes_arp";
	$fp = fopen($file, "r");
	$read = fread($fp, filesize($file));
	$bytes = str_replace(["\n","\r"," "],"",$read);//remove newlines and spaces
	fclose($fp);

	print_r(parse_bytes($bytes));
?>
