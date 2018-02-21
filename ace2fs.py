#!/bin/python
#
########
# ace2fs.py - version: 0.8@16/12/17 demon@demon.com.mx
########
#
# TODO
# check cookie status on vips
# We do need to mark the vips on the name so we can identify them easily
# check ssl status on vips
# mark vips needed for ssl status
# code cleanup

import sys, getopt, re


DEBUG=0
#
# MAIN ROUTINE
#

def main(argv):
	inputfile = ''
	outputfile = ''

	try:
		opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
	except getopt.GetoptError:
		print 'xxxx.py -i <archivo_de_ace> -o <archivo_de_salida>'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'This script tries to translate ace vips into a f5 v 12.x configuration'
			print 'type xxx.py -h for usage parameters'
			print 'demon@demon.com.mx'
			sys.exit()
		elif opt in ("-i", "--ifile"):
			inputfile = arg
		elif opt in ("-o", "--ofile"):
			outputfile = arg

	if not inputfile:
		print "no input file bailing out use -h to get help"
		sys.exit(2)

	# clear globals  <-----

	file_content=list()
	probes=list()
	probes_dict={}


	read_file(inputfile)

	#  WE DON'T CARE ABOUT INTERFACES FOR NOW.
	interfaces_raw=get_section("^interface\svlan\s.*")
	interfaces_dissected=dissect_section("interface\svlan\s.*", interfaces_raw, { 'vlan' : 2, 'interface_data': 0}, "vlan")

	# EXTRACT RSERVERS
	rservers_raw=get_section("^rserver\s.*\s.*")
	rservers_dissected=dissect_section("^rserver\s.*\s.*", rservers_raw, {'rserver_name': 2, 'rserver_data': 0}, "rserver_name")

	# EXTRACT PROBES
	probes_raw=get_section("^probe\s.*\s.*")
	probes_dissected=dissect_section("^probe\s.*\s.*", probes_raw, {'probe_name': 2, 'probe_protocol': 1 , 'probe_data': 0}, "probe_name")

	# EXTRACT SERVERFARMS
	serverfarms_raw=get_section("^serverfarm\shost\s.*")
	serverfarms_dissected=dissect_section("^serverfarm\shost\s.*", serverfarms_raw, {'serverfarm_name': 2, 'serverfarm_data': 0 }, "serverfarm_name")
	#dump_table(serverfarms_dissected)
	stickys_raw=get_section("^sticky\s.*\s.*")

	# START OF HORRIBLE FIXES
	# existen stickies con 2 parametros: sticky layer4-payload ACE-INDIRA-VIP02-pto443-sticky
	# y existen stickies con 3 parametros: sticky http-cookie ACE-DPA-PRO-MOD1 WLB-MATCPROBE-COOKIE-STICKY
	# eliminar el tercer parametro si es que tiene http-cookie para que funcione la lista de vips

	# here again.. encontramos ahora stickies con 5 parametros.. bravo cisco por ser tan homogenea su configuracion
	# porqueria de ace.
	# sticky ip-netmask 255.255.255.255 address source POC-SEG-IDEN-ESTRES-1389-STICKY


	counter=0

	print "fixing stickies.. "

	for items in stickys_raw:
		if re.match("^sticky\slayer4-payload\s.*", items):
			last_param=get_config_line_part(items,2)
			composer="sticky http-cookie " + last_param

		if re.match("^sticky\shttp-cookie\s.*\s.*", items):
			print "......"
			print "buscando sticky en >", items ,"<"
			last_param=get_config_line_part(items,3)
			composer="sticky http-cookie " + last_param
			stickys_raw[counter] = composer # there fixed..
			print "original: "+ items
			print "fixed:"+stickys_raw[counter]

		if re.match("sticky\sip-netmask\s.*", items):
			# tomar el parametro 5 y moverlo al campo 2
			last_param=get_config_line_part(items, 5)
			composer="sticky ip-netmask " + last_param
			stickys_raw[counter] = composer # there fixed..
			print "original: "+ items
			print "fixed:"+stickys_raw[counter]

		counter=counter+1
	# end of horrible fixes
	# I'm Slim Shady, yes I'm the real Shady
	# All you other Slim Shadys are just imitating
	# So won't the real Slim Shady, please stand up,
	# Please stand up,
	# Please stand up

	stickys_dissect=dissect_section("^sticky\s.*\s.*", stickys_raw, {'sticky_name': 2, 'sticky_kind': 1, 'sticky_data': 0 }, "sticky_name")
	#dump_table(stickys_dissect)
	policy_maps_raw=get_section("^policy-map\stype\sloadbalance\sfirst-match.*")


	# ANOTHER HORRIBLE FIX - Cisco ACE don't have a clean and predictable structure
	# Odio a cisco.
	# replace 'loadbalance generic first-match' with 'loadbalance first-match'
	policy_maps_raw2=get_section("^policy-map\stype\sloadbalance\sgeneric.*")
	for index, items in enumerate(policy_maps_raw2):
		#print "items ->", items
		if re.match(".*loadbalance generic first-match.*", items):
			# replace
			save_item=items
			temp_item=items.replace("generic first-match", "first-match")
			policy_maps_raw2[index]=temp_item
			#print "before >", save_item, "<"
			#print "after >", policy_maps_raw[index]
		policy_maps_raw.append(policy_maps_raw2[index])

	policy_maps_dissect=dissect_section("^policy-map\stype\sloadbalance.*", policy_maps_raw, {'policy_map_name': 4, 'policy_map_lb_type': 3, 'policy_map_data': 0 }, "policy_map_name")
	policy_maps_multi_raw=get_section("^policy-map\smulti-match\s.*")
	policy_maps_multi_dissect=dissect_section("^policy-map\smulti-match\s.*", policy_maps_multi_raw, {'policy_map_multi_name': 2, 'policy_map_multi_data': 0 }, "policy_map_multi_name")

	###

	class_temp_table=dissect_again(policy_maps_multi_dissect)
	#dump_table(class_temp_table)
	class_dissect=dissect_section("^class\s.*", class_temp_table , {'class_name': 1, 'class_data':0}, "class_name" )
	#dump_table(class_dissect)
	class_map_raw=get_section("^class-map\s.*")
	class_map_dissected=dissect_section("^class-map\s.*", class_map_raw, {'class_map_name': 2, 'class_map_data': 0 }, "class_map_name")

	### F5 constructs from ACE dissection.

	f5_nodes=explode_rservers(rservers_dissected)
	f5_monitors=explode_probes(probes_dissected)
	f5_pools=explode_serverfarms(serverfarms_dissected, f5_nodes)
	f5_stickies=explode_stickies(stickys_dissect)
	f5_policy_maps=explode_policy_maps(policy_maps_dissect)
	f5_multi_class_maps=explode_multi_class_maps(class_map_dissected)
	f5_class_maps=explode_class_maps(class_map_dissected)

	#dump_table(f5_class_maps)
	#
	#			|
	#			|
	#			V
	#
	#dump_table(f5_multi_class_maps)

	#full_vips=[]
	#for class_maps in f5_class_maps:
	#	class_map_name=class_maps['class_map_name']
	#	full_vips.append(get_ace_vip(class_map_name,f5_class_maps, class_dissect, policy_maps_dissect,serverfarms_dissected,rservers_dissected,f5_stickies))



	# GET INTERFACE VLANS

	#dump_table(interfaces_dissected)
	#for x in interfaces_dissected:
	#	vlan=x['vlan']
	#	interface_data=x['interface_data']
	#	found_data=0
	#	for y in interface_data:
	#		if re.match(".*alias\s.*",y):
	#			found_data=1
	#			#print y
	#			float_ip=get_config_line_part(y,1)
	#			netmask =get_config_line_part(y,2)

	#	if found_data==1:
	#		print vlan + ", " + float_ip + "," + netmask


	#####################################################
	#    SPEW DATA                                      #
	#                                                   #
	#####################################################

	print "============================ DATA ======"



	#dict template
	#spewed_vips_dic="{'vip_ip': vip_ip, 'vip_port': vip_port, 'vip_proto': vip_proto }"

	spewed_vips=[]
	persist_to_spew=[]

	for class_maps in f5_class_maps:

		class_map_name=class_maps['class_map_name']
		#print "processing class " + class_map_name

		vip_to_spew=class_map_name
		vip_struct=get_ace_vip(vip_to_spew,f5_class_maps, class_dissect, policy_maps_dissect,serverfarms_dissected,rservers_dissected,f5_stickies)
		#print "vip struct"
		#print vip_struct
		#print "end vip struct"
		vip_data_found=0
		if vip_struct['vip_found'] == 1:
			vip_data_found=1
			vip_data=[]
			vip_name =  vip_to_spew
			vip_ip   =  vip_struct['vip_ip']
			vip_pool =  vip_struct['vip_serverfarm_name']
			vip_port =  vip_struct['vip_port']

			# hardcoded translation table
			# hay que hacer una tabla real de memoria de traslacion
			# pero al diablo.
			if vip_port == 'www':
				vip_port = "80"

			# buscar la vip en la tabla de spews para no duplicarla
			# posible bug si la vip y el mismo puerto estan en diferentes vlans en ace
			found_spewed=0
			for testvip in spewed_vips:
				this_vip_ip=testvip['vip_ip']
				this_vip_port=testvip['vip_port']
				this_vip_proto=testvip['vip_proto']

				if this_vip_ip == vip_ip and this_vip_port == vip_port:
					# alreway spewed
					found_spewed=1
					break

			if found_spewed == 1:
				continue  # next

			pool_to_find=vip_pool

			if vip_struct['vip_ssl_offload'] == 1:
				vip_data.append("ltm virtual /Common/v_offload_" + vip_name + " {")
			else:
				vip_data.append("ltm virtual /Common/v_" + vip_name + " {")

			vip_data.append("    destination /Common/" + vip_ip + ":" + vip_port)
			vip_data.append("    ip-protocol tcp")
			vip_data.append("    mask 255.255.255.255")

			# BUG.. PERSIST ?
			# no more bug.. here comes persist.....
			#
			# Little darling, it's been a long cold lonely winter
			# Little darling, it feels like years since it's been here
			# Here comes the sun
			# Here comes the sun, and I say
			# It's all right.
			found_sticky=0
			this_is_a_ip_sticky_vip=0
			if vip_struct['vip_cookie'] == 1:
				#print "here i found this vip ", vip_name ," who has a cookie : ", vip_pool
				#print "this cookie name exists on f5_stickies ?"
				# search vip_pool in stickies
				for items in f5_stickies:
					# un


					config=items['sticky_config']
					sticky_server_farm=config['sticky_serverfarm']
					sticky_line=items
					if sticky_server_farm == vip_pool:
						found_sticky=1

						# validar el tipo de sticky, si es ip-netmask marcar el pool o la vip
						# para escupirla generica

						#if config['sticky_kind'] == "ip-netmask":
						#	# el vip_pool es el serverfarm contenido
						#	dump_table(config)
						#	exit(0)


						sticky_name=items['sticky_name']

						# fix para el ip-netmask

						#print "==========================="
						#print items['sticky_kindy']

						if items['sticky_kindy'] == "ip-netmask":
							this_is_a_ip_sticky_vip=1
							#print "this is a ip sticky <_______________"


						if items['sticky_kindy'] != "http-cookie":
							#print "BUG.. esta virtual ", vip_name, "tiene un cookie pero no es http !!.. "
							#print "no se que hacer.. muero.. arregle su desastrito.. bye.."
							#print "convirtiendo a http"
							items['sticky_kindy'] = "http-cookie"
							#print "fixing this shit"
							#print items
							#exit(1)
						break

				if found_sticky == 0:
					print "ERROR - EL PROCESAMEINTO TERMINA AQUI, CORRIJA EL ARCHIVO Y EJECUTE DE NUEVO"
					print "BUG .. esta virtual ", vip_name, "tiene un profile de persistencia, pero no existe ese profile..."
					print "no se que hacer.. muero.. arregle su desastrito.. bye.."
					exit(1)


				if this_is_a_ip_sticky_vip:
					#print "inside.."
					vip_data.append("    persist {")
					vip_data.append("        /Common/source_addr {")
					vip_data.append("            default yes")
					vip_data.append("        }")
					vip_data.append("    }")
					persist_to_spew.append(sticky_name)
				else:
					vip_data.append("    persist {")
					compose_persist="        /Common/" + sticky_name
					vip_data.append(compose_persist)
					vip_data.append("            default yes")
					vip_data.append("        }")
					vip_data.append("    }")
					persist_to_spew.append(sticky_name)

				#dump_table(f5_stickies)
				# buscar el sticky_serverfarm, debe de ser igual al vip_pool
				# el sticky_name es el nombre del profile de cookie a crear, agregar cookie_
				# agregar el sticky_name para despues escupir persistencias de cookies

			vip_data.append("    pool p_" + vip_pool )

			if found_sticky == 1 and this_is_a_ip_sticky_vip == 0:
				# agregar el profile de http
				vip_data.append("    profiles {")
				vip_data.append("        /Common/http { }")
				vip_data.append("    }")

			if found_sticky == 1 and this_is_a_ip_sticky_vip == 1:
				# agregar el profile de tcp
				vip_data.append("    profiles {")
				vip_data.append("        /Common/tcp { }")
				vip_data.append("    }")
				vip_data.append("    source 0.0.0.0/0")
				vip_data.append("    translate-address enabled")
				vip_data.append("    translate-port enabled")
				vip_data.append("}")
				vip_data.append("")


			# bug.. profiles !! ???.. bueno no es un bug tan grande el unico profile que hardcodeamos es http

			#bug===> vip_proto = tcp
			vip_proto="tcp"
			spewed_vips_dic={'vip_ip': vip_ip, 'vip_port': vip_port, 'vip_proto': vip_proto }
			spewed_vips.append(spewed_vips_dic)

		#print "============= here is your data =============="
		if vip_data_found == 1:
			dump_table(vip_data)
			dummy_pool, dummy_nodes, dummy_monitor=spew_pool(vip_pool, f5_pools, f5_nodes, f5_monitors, vip_port)
			#print "here is " + pool_to_find + " -------------------"
			dump_table(dummy_pool)
			for items in dummy_nodes:
				for node_data in items:
					print node_data
				print ""
			dump_table(dummy_monitor)

			# el mismo nombre del sticky es el nombre de la cookie..
			if found_sticky == 1 and this_is_a_ip_sticky_vip == 0:
				print "ltm persistence cookie /Common/" + sticky_name + " {"
				print "    always-send disabled"
				print "    app-service none"
				print "    cookie-name " + sticky_name
				print "    defaults-from /Common/cookie"
				print "    expiration 43:0"
				print "    method insert"
				print "    override-connection-limit disabled"
				print "}"
				#print sticky_line
				#exit(0)





#ltm persistence cookie /Common/AGGCUAT_STICKY_TCP80 {
#    always-send disabled
#    app-service none
#    cookie-name F5-CONTENCION-AGGCUAT-80
#    defaults-from /Common/cookie
#    expiration 43:0
#    method insert
#    override-connection-limit disabled
#}


	#dump_table(f5_stickies)  ### HAY QUE PEGAR LOS STICKIES Y LO DE SSL
	#dummy_node=spew_node("dummy",f5_nodes)
	#dump_table(dummy_node)
	#dump_table(f5_pools)
	# SPEW POOLS
	#pool_to_find="FARM-AMIS-UAT-144"
	#dummy_pool, dummy_nodes, dummy_monitor=spew_pool("FARM-AMIS-UAT-1443", f5_pools, f5_nodes, f5_monitors)

	#print "here is " + pool_to_find + " -------------------"
	#dump_table(dummy_pool)
	#for items in dummy_nodes:
	#	for node_data in items:
	#		print node_data
	#print ""
	#dump_table(dummy_monitor)

	#dump_table(f5_class_maps)

	#########################################
	# stickies de la virtual
	# profiles de la virtual
	# monitor no obtiene el get url data ni el host

	#dump_table(rservers_raw)
### stickies a la virtual
	#dump_table(f5_stickies)
	#policy_maps_multi -> loadbalance policy

	#print search_sticky("FOPAI-PIAS-RECHUM-01-STICKY_30600_cambio",f5_stickies)
	#dump_table(stickys_raw)

# los stickies son por serverfarm no por virtual.
# encontrar la relacion serverfarm -> virtual y agregar el nombre del sticky en la estructrua de datos
# ^
# |
# done en persist bug

##### CERTIFICADOS #####



def spew_pool (pool_name, f5_pools, f5_nodes, f5_monitors, vip_port):
	this_pool_data=[]
	pool_to_search=pool_name
	pool_nodes_found=0
	pool_monitor_found=0
	for items in f5_pools:
		pool_name=items['pool_name']
		if pool_name == pool_to_search:
			pool_description=items['pool_description']
			pool_monitor    =items['pool_monitor']
			pool_members    =items['pool_members']
			pool_lb_method  =items['pool_lb_method']

			this_pool_data.append("ltm pool /Common/p_" + pool_name + " {")

			if pool_lb_method == "leastconns":
				this_pool_data.append("    load-balancing-mode least-connections-member")

			if len(pool_members) > 0:
				# there are members
				pool_nodes=[]
				this_pool_data.append("    members {")
				for member in pool_members:
					node_name        = member['node_name']
					node_ip          = member['node_ip']
					node_inservice   = member['node_inservice']
					node_description = member['node_description']

					this_pool_data.append("        /Common/n_" + node_name + ":" + vip_port + " {")
					this_pool_data.append("            address " + node_ip)
					this_pool_data.append("        }")
					pool_nodes_found=1
					pool_nodes.append(node_name)

				this_pool_data.append("    }")

			if pool_monitor:
				this_pool_data.append("    monitor /Common/m_" + pool_monitor)
				pool_monitor_found=1

			this_pool_data.append("}")
			this_pool_data.append("")
			break

	if pool_nodes_found == 1:
		nodes_construct=[]
		for nodes in pool_nodes:
			#print "looking for :" + nodes
			nodes_construct.append(spew_node(nodes,f5_nodes))
	else:
		print "errror amrmando el pool : ", pool_name
		exit(1)


	if pool_monitor_found == 1:
		monitor_construct=spew_probe(pool_monitor,f5_monitors)
	else:
		monitor_construct=[]


	return this_pool_data, nodes_construct, monitor_construct


def spew_probe (probe_name, f5_monitors):
	this_monitor_data=[]
	probe_to_search=probe_name
	for items in f5_monitors:
		monitor_name=items['monitor_name']
		monitor_port_found=0
		monitor_get_url=""
		monitor_host_header=""
		if monitor_name == probe_to_search:
			monitor_type     = items['monitor_type']
			monitor_port     = items['monitor_port']
			monitor_interval = items['monitor_interval']
			monitor_request  = items['monitor_request']
			monitor_header   = items['monitor_header']
			monitor_expect   = items['monitor_expect']
			monitor_timeout  = items['monitor_timeout']

			#print "monitor timeout -> "
			#print  monitor_timeout

			if monitor_port.strip():
				monitor_port_found = 1

			#print monitor_name
			#print monitor_request

			# FIX Cisco ASA lack of port
			if not monitor_port:
				monitor_port="*"

			monitor_get_url_found=0

			if  not monitor_expect.strip():
				monitor_expect_status_found=0
			else:
				monitor_expect_status_found=1

			if not monitor_header.strip():
				monitor_host_header_found=0
			else:
				monitor_host_header_found=1

			if not monitor_request.strip():
				monitor_get_url_found=0
			else:
				monitor_get_url_found=1


			if monitor_type == "http":
				#print "http monitor"
				this_monitor_data.append("ltm monitor http /Common/m_" + monitor_name + " {")
				this_monitor_data.append("    adaptive disabled")
				this_monitor_data.append("    defaults-from /Common/http")
				this_monitor_data.append("    destination *:" + monitor_port)
				this_monitor_data.append("    interval " + monitor_interval)
				this_monitor_data.append("    ip-dscp 0")
				if monitor_get_url_found == 1 and monitor_host_header_found == 0:
					construct="    send \"GET " + monitor_request + " HTTP/1.1\\r\\nConnection: close\\r\\n\\r\\n "
					this_monitor_data.append(construct)
				if monitor_get_url_found == 1 and monitor_host_header_found == 1:
					construct="    send \"GET " + monitor_request + " HTTP/1.1\\r\\nHost: "
					construct=construct + monitor_header + "\\r\\nConnection: close\\r\\n\\r\\n\""
					this_monitor_data.append(construct)
				if monitor_expect_status_found == 1:
					this_monitor_data.append("    recv " + monitor_expect )
					this_monitor_data.append("    recv-disable none")
				this_monitor_data.append("    time-until-up 0")
				this_monitor_data.append("    timeout " + str(monitor_timeout))
				this_monitor_data.append("}")

		#ltm monitor tcp /Common/TCP_80 {
        #    #   adaptive disabled
        #    #   defaults-from /Common/tcp
        #    #   destination *:80
        #    #   interval 30
        #    #   ip-dscp 0
        #    #   recv none
        #    #   recv-disable none
        #    #   send none
        #    #   time-until-up 0
        #    #   timeout 35
		# 	#}
		#
			if monitor_type == "tcp":

				if not monitor_port:
					monitor_port="*"

				#print "tcp monitor"
				this_monitor_data.append("ltm monitor tcp /Common/m_" + monitor_name + " {")
				this_monitor_data.append("    adaptive disabled")
				this_monitor_data.append("    defaults-from /Common/tcp")
				#if monitor_port_found == 1:
				this_monitor_data.append("    destination *:" + monitor_port)
				#else:
				#	this_monitor_data.append("    destination *:*")
				this_monitor_data.append("    interval " + monitor_interval)
				this_monitor_data.append("    ip-dscp 0")
				this_monitor_data.append("    recv none")
				this_monitor_data.append("    send none")
				this_monitor_data.append("    time-until-up 0")
				this_monitor_data.append("    timeout " + str(monitor_timeout))
				this_monitor_data.append("}")
		#
		#
		# 	#ltm monitor https /Common/MONITOR_SIAT_RFS_AUTH-443 {
		# 	#    adaptive disabled
		# 	#    cipherlist DEFAULT:+SHA:+3DES:+kEDH
		# 	#    compatibility enabled
		# 	#    defaults-from /Common/https
		# 	#    destination *:*
		# 	#    interval 30
		# 	#    ip-dscp 0
		# 	#    recv 200
		# 	#    recv-disable none
		# 	#    send "GET /nidp/app/heartbeat HTTP/1.1\\r\\nHost: xxxx\\r\\nConnection: Close\\r\\n\\r\\n"
		# 	#    time-until-up 0
		# 	#    timeout 10
		# 	#}
		#
			if monitor_type == "https":
				#print "https monitor"
				this_monitor_data.append("ltm monitor https /Common/m_" + monitor_name + " {")
				this_monitor_data.append("    adaptive disabled")
				this_monitor_data.append("    cipherlist DEFAULT:+SHA:+3DES:+kEDH")
				this_monitor_data.append("    compatibility enabled")
				this_monitor_data.append("    defaults-from /Common/https")
				if monitor_port_found == 1:
					this_monitor_data.append("    destination *:" + monitor_port)
					this_monitor_data.append("    interval " + monitor_interval)
					this_monitor_data.append("    ip-dscp 0")
				if monitor_get_url_found == 1 and monitor_host_header_found == 1:
					construct="    send \"GET " + monitor_request + " HTTP/1.1\\r\\nHost: "
					construct=construct + monitor_header + "\\r\\nConnection: close\\r\\n\\r\\n\""
					this_monitor_data.append(construct)
				if monitor_expect_status_found == 1:
					this_monitor_data.append("    recv " + monitor_expect )
					this_monitor_data.append("    recv-disable none")
				this_monitor_data.append("    time-until-up 0")

				this_monitor_data.append("    timeout " + monitor_interval)

				this_monitor_data.append("}")

			break
		#
	return this_monitor_data


def spew_node(node_to_find, f5_nodes):
	this_node_data=[]
	node_to_search=node_to_find
	for items in f5_nodes:
		node_name=items['node_name']
		if node_to_search == node_name:
			node_config      = items['node_config']
			node_description = node_config['node_description']
			node_description.replace("  description ","",1)
			node_inservice   = node_config['node_inservice']
			node_ip          = node_config['node_ip']

			if node_inservice == 1:
				this_node_data.append("ltm node /Common/n_" + node_name + " {")
				this_node_data.append("    address " + node_ip)
				this_node_data.append("}")

			break

	return this_node_data






def search_sticky(sticky_to_search, stickies_table):
	return_data=""
	for items in stickies_table:
		if items['sticky_name'] == sticky_to_search:
			break

	return items


def get_ace_vip(vip_to_search,f5_class_maps, class_dissect, policy_maps_dissect,serverfarms_dissected,rservers_dissected,f5_stickies):
	#vip_to_search="CLASS-pre-ex-uat-9084-C"
	#print ""
	#print " ---- TEST ----"
	#print "vamos a buscar esta vip: " + vip_to_search

	stop_on_vip=1
	vip_node_dict=""

	vip_data=search_vip(vip_to_search, f5_class_maps)
	#print vip_data
	vip_port=vip_data['class_map_port']
	vip_ip  =vip_data['class_map_vip']
	vip_name=vip_data['class_map_name']

	#dump_table(policy_maps_multi_raw)
	#dump_table(class_dissect)

	# buscar vip_name en class_dissect

	found_class=0
	for items in class_dissect:
		#print items
		#print vip_name
		if items['class_name'] == vip_name:
		#this is it return full line
			return_item=dict(items)
			found_class=1
			break

	vip_alive=0
	vip_policy_to_serverfarm=""
	vip_found_policy=0
	vip_ssl_offload=0

	vip_return_structure={  'vip_ip'   : '',
	                        'vip_found': 0,
	                        'vip_name' : vip_to_search,
							'vip_port' : '',
							'vip_nodes_table' : [],
	                        'vip_cookie' : 0 }

	if found_class:
		#print "encontre esta vip: " + vip_name
		#print "ip: " + vip_ip
		#print " puerto: " + vip_port
		#print "policy: "
		subitem=return_item['class_data']
		for items in subitem:
			#buscar si esta en servicio
			# buscar el policy
			# buscar si contesta a ping
			#print items
			if re.match(".*loadbalance\svip\sinservice.*", items):
				vip_alive=1
				#print "vip ", vip_name, " esta viva !!"

			if re.match(".*loadbalance\spolicy.*",items):
				vip_found_policy=1
				#print items
				vip_policy_to_serverfarm=get_config_line_part(items,2)
				#print "policty " + vip_policy_to_serverfarm

			if re.match(".*ssl-proxy\sserver\s", items):
				vip_ssl_offload=1
				#print "encontre un ssl proxy en ", vip_name
				#exit(1)

		if vip_alive == 1:
			#print "policy to serverfarm : " + vip_policy_to_serverfarm

			# buscar el policy en policymaps ahi obtenemos el server farm

			#dump_table(policy_maps_dissect)
			policy_map_found=0
			for pm_items in policy_maps_dissect:
				if pm_items['policy_map_name'] == vip_policy_to_serverfarm:
					policy_map_found=1
					policy_map_data=pm_items['policy_map_data']
					break

			sticky_sf_found=0
			normal_sf_found=0
			serverfarm_name=""

			if policy_map_found:
				for pm2_items in policy_map_data:
					if re.match(".*sticky-serverfarm\s.*",pm2_items):
						sticky_sf_found=1
						sticky_sf_name=get_config_line_part(pm2_items,1)
						serverfarm_name=sticky_sf_name
						#print "sticky_server_farm found: " + sticky_sf_name
					if re.match(".*\sserverfarm\s.*",pm2_items):
						normal_sf_found=1
						normal_sf_name=get_config_line_part(pm2_items,1)
						serverfarm_name=normal_sf_name
					if re.match(".*class\s.*",pm2_items):
						pm_class=get_config_line_part(pm2_items,1)



				if sticky_sf_found:
					#print "sticky serverfarm: " + sticky_sf_name
					#dump_table(f5_stickies)
					#search for serverfarm in stickies.
					sticky_serverfarm_found=0
					for items in f5_stickies:
						if items['sticky_name'] == serverfarm_name:  # unpack
							sticky_config=items['sticky_config']
							sticky_serverfarm=sticky_config['sticky_serverfarm']
							normal_sf_found=1
							normal_sf_name=sticky_serverfarm
							serverfarm_name=sticky_serverfarm
							sticky_serverfam_found=1
							#print "serverfarm: " + normal_sf_name
							break;
					if sticky_serverfarm_found==0:
						serverfarm_found=0
						# vip sin servicio

				if normal_sf_found:
					#
					# print "serverfarm: " + normal_sf_name
					serverfarm_found=0
					for serverfarms in serverfarms_dissected:
						if serverfarms['serverfarm_name'] == serverfarm_name:
							serverfarm_found=1
							serverfarm_data=serverfarms['serverfarm_data']
							break
				else:
					serverfarm_found=0

				vip_node_dict= {'vip_name': vip_name,
				                'vip_port': vip_port,
				                'vip_ip'  : vip_ip,
				                'vip_nodes' : [] }

				if serverfarm_found:
					# empty nodes table
					nodes_table=[]
					for sf_data_item in serverfarm_data:
						if re.match("^\s*rserver\s*",sf_data_item):
							nodes_table.append(get_config_line_part(sf_data_item,1))

					#print "nodes :"

					#dump_table(nodes_table)


					vip_nodes_table=[]
					for node_to_find in nodes_table:
						vip_nodes_table.append(search_node(node_to_find,rservers_dissected))

					for final_nodes in vip_nodes_table:
						node_name       =final_nodes['node_name']
						node_found      =final_nodes['node_found']
						node_inservice  =final_nodes['node_inservice']
						node_description=final_nodes['node_description']
						node_ip         =final_nodes['node_ip']
				else:
					if stop_on_vip == 1:
						print " ERROR - EL PROCESAMEINTO TERMINA AQUI, CORRIJA EL ARCHIVO Y EJECUTE DE NUEVO"
						print " no serverfarm found ", vip_name, " serverfarm referenciado : ", serverfarm_name
						print "no se incluyo la vip ", vip_name, " arregle su porqueria de configuracion de ACE"
						exit(1)
					vip_alive=0
					vip_nodes_table=[]

					#dump_table(rservers_dissected)
			else:
				vip_alive=0
				if stop_on_vip == 1:
					print "no policy map ", vip_name
					exit(1)
				vip_nodes_table=[]


			#return table object
			vip_return_structure={  'vip_ip'   : vip_ip,
			                        'vip_found': vip_alive,
			                        'vip_name' : vip_name,
									'vip_port' : vip_port,
									'vip_nodes_table' : vip_nodes_table,
			                        'vip_serverfarm_name' : serverfarm_name,
			                        'vip_cookie' : sticky_sf_found,
			                        'vip_ssl_offload' : vip_ssl_offload }

	return vip_return_structure



def search_node(node_to_find, nodes_table):
	found_node=0

	node_struct= { 'node_ip' : "",
	               'node_inservice': 0,
	               'node_name': node_to_find,
	               'node_description': "",
	               'node_found' : 0}

	for items in nodes_table:
		#print items
		if items['rserver_name'] == node_to_find:
			node_struct['node_name'] = node_to_find
			node_data=items['rserver_data']
			found_node=1
			break

	node_ip_found=0
	node_ip=""
	node_inservice=0
	node_description=""

	if found_node:
		for items in node_data:
			#print ">"+items+"<"
			if re.match("^\s*ip\saddress.*",items):
				node_ip_found=1
				node_ip=get_config_line_part(items,2)
				#print "found node ip ->" + node_ip + "<"

			if re.match("^\s*inservice.*", items):
				node_inservice=1

			if re.match("^\s*description.*", items):
				node_description=items


	node_struct= { 'node_ip' : node_ip,
	               'node_inservice': node_inservice,
	               'node_name': node_to_find,
	               'node_description': node_description,
	               'node_found' : found_node }

	return node_struct


#sticky_data_dic = "" #empty structure

#			sticky_data_dic = {'sticky_cookie_insert': sticky_cookie_insert,
#			 'sticky_cookie_insert_browser_expire': sticky_cookie_insert_browser_expire,
#			 'sticky_response_sticky': sticky_response_sticky,
#			 'sticky_l4_payload': sticky_l4_payload,
#			 'sticky_replicate': sticky_replicate,
#				# 	 'sticky_timeout': sticky_timeout,
#			 'sticky_serverfarm': sticky_serverfarm }



###--------------------------
###--------------------------
###--------------------------
###--------------------------
###--------------------------




	# we have the vip on class_map_vip, and the name on class_map_name
	# search for the name on class table

	#build_vip("VIP_SCCCYG_AMBIENTE_DESARROLLO_pto9080", f5_class_maps)


	#node_dummy=get_node('vorindev-08', f5_nodes)
	#if not node_dummy:
	#	print "node not found"
	#else:
	#	print "node found"
	#	print node_dummy

	# loop, thru pmmulti_dissected
	# get policy_map_multi_data
	# if ^\Sclass\s.*, ltrim class  -> write in new table
	# use normal dissect on this new table...

	# write in ram table {'class_multi_name': 1, 'class_multi_data': 0, 'class_multi_name' )

	#policy-map multi-match

	#crypto_chain=get_section("^crypto\schaingroup\s.*")

	#print "crypto raw -------"
	#for items in crypto_chain:
	#	print items
	#print "crypto raw -------"

	#interface_vlan=get_section("^interface\svlan\s.*")

	#print "interface raw -------"
	#for items in interface_vlan:
	#	print items
	#print "interface raw -------"

	#rserver_raw=get_section("^rserver\s.*\s.*")

	#for items in rserver_raw:
	#	print items


	#serverfarm_raw=get_section("^serverfarm\s.*\s.*")

	#for items in serverfarm_raw:
	#	print items


	#interface_vlans_raw=get_section("^interface vlan\s.*")

	#for items in interface_vlans_raw:
	#	print items

	#probes_dissected=dissect_section("^probe\s.*\s.*", probes_raw, {'probe_name': 2, 'probe_protocol': 1 , 'probe_data': 0}, "probe_name")

	#for items in probes_dissected:
	#	print items

	#rservers_dissected=dissect_section("^rserver\s.*\s.*", rserver_raw, { 'rserver_name': 2, 'rserver_data': 0 }, 'rserver_name')


	#for items in rservers_dissected:
	#	print items


#
# CONFIG SECTION EXTRACTION ROUTINES
#


# probes/monitor template
#ltm monitor https /Common/MONITOR_SIAT_RFS_AUTH-443 {
#    adaptive disabled
#    cipherlist DEFAULT:+SHA:+3DES:+kEDH
#    compatibility enabled
#    defaults-from /Common/https
#    destination *:*
#    interval 30
#    ip-dscp 0
#    recv 200
#    recv-disable none
#    send "GET /nidp/app/heartbeat HTTP/1.1\\r\\nHost:xxxx\\r\\nConnection: Close\\r\\n\\r\\n"
#    time-until-up 0
#    timeout 10
#}

#ltm monitor http /Common/Probexxxxx.yyy.mx_80 {
#    adaptive disabled
#    defaults-from /Common/http
#    destination *:80
#    interval 30
#    ip-dscp 0
#    recv 302
#    recv-disable none
#    send "GET /nesp/app/heartbeat HTTP/1.1\r\nHost: xxxxx.com \r\nConnection: close\r\n\r\n"
#    time-until-up 0
#    timeout 91
#}

#ltm monitor tcp /Common/xxxxxxx {
#    adaptive disabled
#    defaults-from /Common/tcp
#    destination *:*
#    interval 60
#    ip-dscp 0
#    recv none
#    recv-disable none
#    send none
#    time-until-up 0
#    timeout 181
#}

# agregar icmp al nodo si el probe es icmp <-------- LATER

#def build_vip(vip_name, f5_class_maps):

#	f5_vip_table=[]
#	# buscar la ip en f5_class_maps o class maps multi
#	vip_data=search_vip(vip_name, f5_class_maps)
#	if vip_data:
#		print "vip data ->", vip_data, "<"
#	else:
#		print "VIP NAME ", vip_name, " NOT FOUND "
#		break

#	vip_ip=vip_data['class_map_vip']
#	vip_port=vip_data['class_map_port']
#	vip_type=vip_data['class_map_type']
#	print "ltm virtual /Common/", vip_name
#	print "    destination/Common/", vip_ip,":", vip_port
#	print "    ip-protocol ", vip_type
#	print "    mask 255.255.255.255"  # <- BUG HARDCODED
#	# process persist


	# get pool

#	get_pool_data

	# process profiles

# ltm virtual /Common/VIP_sdfsf {
#     destination /Common/10.56.18.151:443
#     ip-protocol tcp
#     mask 255.255.255.255
#     persist {
#         /Common/F5-sdfq {
#             default yes
#         }
#     }
#     pool /Common/FARM_APLICACIONES_PTO443
#     profiles {
#         /Common/sdfT {
#             context clientside
#         }
#         /Common/sdf {
#             context serverside
#         }
#         /Common/http { }
#         /Common/tcp { }
#     }
#     source 0.0.0.0/0
#     translate-address enabled
#     translate-port enabled
# }

#def search_policy_map(vip_name, f5_policy_maps):
#	found_policy_map=0
#	for items in f5_policy_maps:
#		if items['']



def search_vip(vip_name, f5_class_maps):
	found_vip=0
	return_item=""
	for items in f5_class_maps:
		if items['class_map_name'] == vip_name:
			#this is it return full line
			return_item=dict(items)
			break
	return return_item


def explode_class_maps(class_map_dissected):

# DICT STRUCT
# { 'class_map_name': class_map_name,
#	'class_map_vip': class_map_vip,
#   'class_map_type': class_map_type,
#   'class_map_port': class_map_port,
#   'class_map_range': class_map_range,
#   'class_map_description': class_map_description }'
	f5_class_maps=[]
	class_map_range=""
	class_map_description=""
	for items in class_map_dissected:
		class_map_name=items['class_map_name']
		class_map_data=items['class_map_data']
		class_map_range=""
		class_map_description=""
		class_map_vip=""
		class_map_port=""
		class_map_type=""
		if class_map_name != 'management':
			for config_item in class_map_data:
				if re.match(".*\svirtual-address\s.*", config_item):
					class_map_vip=get_config_line_part(config_item,3)
					class_map_type=get_config_line_part(config_item,4)
					class_map_port=get_config_line_part(config_item,6)
					if re.match(".*\srange\s.*", config_item):
						cl_map_range=get_config_line_part(config_item,6)
						cl_map_range1=get_config_line_part(config_item,7)
						class_map_range=cl_map_range + " " + cl_map_range1

				if re.match("^\s\sdescription\s", config_item):
					class_map_description=config_item


			f5_class_maps.append( { 'class_map_name': class_map_name,
			                        'class_map_vip': class_map_vip,
			                        'class_map_type': class_map_type,
			                        'class_map_port': class_map_port,
			                        'class_map_range': class_map_range,
			                        'class_map_description': class_map_description } )

			#print "created class : "+ class_map_name

	return f5_class_maps



# spew monitors
def explode_multi_class_maps(class_map_dissected):

# DICT STRUCT
# { 'class_map_name': class_map_name,
#   'class_vip_address': class_vip_address,
#   'class_type_port': class_type_port,
#   'class_port_number': class_port_number,
#   'class_full_line': class_full_line,
#   'class_description': class_description }

	f5_class_maps=[]
	class_vip_address=""
	class_type_port=""
	class_port_number=""
	class_full_line=""
	class_description=""
	for table_item in class_map_dissected:
		class_map_name=table_item['class_map_name']
		class_map_data=table_item['class_map_data']
		for config_item in class_map_data:
			# ignore "management" class maps
			if class_map_name == 'management':
				sw_save=0
				continue
			else:
				sw_save=1
				if re.match(".*virtual-address\s.*", config_item):
					class_vip_address=get_config_line_part(config_item,3)
					class_type_port=get_config_line_part(config_item,4)
					class_port_number=get_config_line_part(config_item,6)
					class_full_line=config_item
					class_vip_address_found=1

				if re.match(".*description\s.*", config_item):
					class_description=get_config_line_part(config_item,1)
					class_description_found=1

		if sw_save:
			f5_class_maps.append( { 'class_map_name': class_map_name,
		                            'class_vip_address': class_vip_address,
		                            'class_type_port': class_type_port,
		                            'class_port_number': class_port_number,
		                            'class_full_line': class_full_line,
		                            'class_description': class_description } )
	return f5_class_maps




def explode_policy_maps(policy_maps_dissect):
	# 	{ 'policy_map_name': policy_map_name, 'policy_map_class': policy_map_class, 'policy_map_sticky_serverfarm': policy_map_serverfarm }
	f5_policy_maps=[]
	for table_item in policy_maps_dissect:
		policy_map_name=table_item['policy_map_name']
		policy_map_data=table_item['policy_map_data']
		policy_map_lb_type=table_item['policy_map_lb_type']
		policy_map_class=""
		policy_map_sticky_serverfarm=""
		policy_map_serverfarm=""
		policy_map_ssl_proxy=""
		for policy_map_config in policy_map_data:
			if re.match("^\s\sclass\s.*", policy_map_config):
				policy_map_class=get_config_line_part(policy_map_config,1)
				policy_map_class_found=1

			if re.match(".*serverfarm\s.*", policy_map_config):
				if re.match(".*sticky-serverfarm\s.*", policy_map_config):
					policy_map_sticky_serverfarm=get_config_line_part(policy_map_config,1)
					policy_map_sticky_serverfarm_found=1
				else:
					policy_map_serverfarm=get_config_line_part(policy_map_config,1)
					policy_map_serverfarm_found=1

			if re.match("%\s\sssl-proxy.*", policy_map_config):
				policy_map_ssl_proxy=get_config_line_part(policy_map_config) # <-- BUG decode later
				policy_map_ssl_proxy_found=1


		f5_policy_maps.append( { 'policy_map_name': policy_map_name,
		                         'policy_map_lb_type': policy_map_lb_type,
		                         'policy_map_class': policy_map_class,
		                         'policy_map_sticky_serverfarm': policy_map_sticky_serverfarm,
		                         'policy_map_serverfarm': policy_map_serverfarm,
		                         'policy_map_ssl_proxy': policy_map_ssl_proxy } )

	return f5_policy_maps




def explode_stickies(stickys_dissect):
	f5_stickies=[]
	#dump_table(stickys_dissect)
	for table_item in stickys_dissect:
		sticky_name=table_item['sticky_name']
		sticky_kind=table_item['sticky_kind']
		sticky_data=table_item['sticky_data']

		sticky_cookie_insert=0
		sticky_replicate=0
		sticky_cookie_insert_browser_expire=0
		sticky_response_sticky=0
		sticky_l4_payload=""
		sticky_timeout=0
		sticky_serverfarm=""

		#if sticky_name == "WLB-MATCPROBE-COOKIE-STICKY":
		#	print "stop here"

		for sticky_items in sticky_data:
			if re.match("^\s\stimeout\s.*", sticky_items ):
				sticky_timeout=get_config_line_part(sticky_items,1)
				sticky_timeout_found=1

			if re.match("^\s\sreplicate\ssticky.*", sticky_items):
				sticky_replicate=1
				sticky_replicate_found=1

			if re.match("^\s\sserverfarm\s.*", sticky_items):
				sticky_serverfarm=get_config_line_part(sticky_items,1)
				sticky_serverfarm_found=1

			if re.match("^\s\scookie\sinsert.*", sticky_items):
				if re.match(".*browser-expire.*", sticky_items):
					sticky_cookie_insert_browser_expire=1
					sticky_cookie_insert_browser_expire_found=1
				else:
					sticky_cookie_insert=1
					sticky_cookie_insert_found=1

			if re.match("^\s\sresponse\ssticky.*", sticky_items):
				sticky_response_sticky=1
				sticky_response_sticky_found=1

			if re.match("^\s\slayer4-payload\s.*", sticky_items):
				sticky_l4_payload=sticky_items
				sticky_l4_payload_found=1

			sticky_data_dic = "" #empty structure

			sticky_data_dic = {'sticky_cookie_insert': sticky_cookie_insert,
			 'sticky_cookie_insert_browser_expire': sticky_cookie_insert_browser_expire,
			 'sticky_response_sticky': sticky_response_sticky,
			 'sticky_l4_payload': sticky_l4_payload,
			 'sticky_replicate': sticky_replicate,
			 'sticky_timeout': sticky_timeout,
			 'sticky_serverfarm': sticky_serverfarm }

		f5_stickies.append({ 'sticky_name': sticky_name,
		                     'sticky_kindy': sticky_kind,
		                     'sticky_config': sticky_data_dic } )
	return f5_stickies
	# returns
	# {'sticky_config': {'sticky_timeout': '600', 'sticky_cookie_insert_browser_expire': 0, 'sticky_l4_payload': '  layer4-payload offset 43 length 32 begin-pattern "\\x20|\\x00\\xST)"\r', 'sticky_response_sticky': 1, 'sticky_cookie_insert': 0, 'sticky_serverfarm': 'FARM-EF-DEV-PTO443', 'sticky_replicate': 1}, 'sticky_kindy': 'layer4-payload', 'sticky_name': 'STICKY_SSL_EF-DEV-PTO443'}


def explode_probes(probes_dissected):
	this_monitor_data=[]  # <- check
	f5_monitors=[]
	for table_item in probes_dissected:
		if DEBUG:
			print table_item
		monitor_name=table_item['probe_name']
		monitor_type=table_item['probe_protocol']
		monitor_data=table_item['probe_data']
		monitor_port_found=0
		monitor_get_url_found=0
		monitor_expect_status_found=0
		monitor_pass_detect_interval_found=0
		monitor_host_header_found=0
		port_found=1
		if DEBUG:
			print "probe/monitor name ", monitor_name
			print "probe/monitor type ", monitor_type

		for probe_config_item in monitor_data:
			#look for port
			################# HERE ###
			# fucking python don't have switch/case constructors.. i hate if's for this
			if re.match("^\s\sport\s.*", probe_config_item):
				monitor_port=get_config_line_part(probe_config_item,1)
				monitor_port_found=1

			if re.match("^\s\sinterval\s.*", probe_config_item):
				monitor_interval=get_config_line_part(probe_config_item,1)
				monitor_interval_found=1

			if re.match(".*passdetect\sinterval\s*",probe_config_item):
				monitor_pass_detect_interval=get_config_line_part(probe_config_item,2)
				monitor_pass_detect_interval_found=1

			if re.match(".*faildetect\s.*",probe_config_item):
				monitor_fail_detect=get_config_line_part(probe_config_item,1)
				monitor_fail_detect_found=1

			if re.match(".*passdetect\scount.*", probe_config_item):
				monitor_pass_detect_count=get_config_line_part(probe_config_item,2)
				monitor_pass_detect_count_found=1

			if re.match(".*passdetect\sinterval.*", probe_config_item):
				monitor_pass_detect_interval=get_config_line_part(probe_config_item,2)
				monitor_pass_detect_count_found=1

			if re.match(".*request\smethod\sget.*", probe_config_item):
				monitor_get_url=get_config_line_part(probe_config_item,4)
				monitor_get_url_found=1

			if re.match(".*expect\sstatus.*", probe_config_item):
				monitor_expect_status1=get_config_line_part(probe_config_item,2)
				monitor_expect_status2=get_config_line_part(probe_config_item,3)
				monitor_expect_status_found=1

			if re.match(".*header\sHost\sheader-value.*", probe_config_item):
				monitor_host_header=get_config_line_part(probe_config_item,3)
				monitor_host_header_found=1


			# no monitor pass detect unbound variable monitor_passdetect_interval.. fix
			if monitor_pass_detect_interval_found == 0:
				monitor_pass_detect_interval = 15

			if monitor_get_url_found == 0:
				monitor_get_url = ""

			if monitor_expect_status_found == 0:
				monitor_expect_status1 = ""
				monitor_expect_status2 = ""

			if monitor_host_header_found == 0:
				monitor_host_header = ""

			if monitor_port_found == 0:
				monitor_port=""

		f5_monitors.append({ 'monitor_name': monitor_name, 'monitor_type': monitor_type, 'monitor_port': monitor_port, 'monitor_interval': monitor_interval, 'monitor_timeout': monitor_pass_detect_interval, 'monitor_request': monitor_get_url, 'monitor_expect': monitor_expect_status1, 'monitor_header': monitor_host_header } )

			# create common http monitor
			#ltm monitor http /Common/Probe_fhghjgj80 {
			#    adaptive disabled
			#    defaults-from /Common/http
			#    destination *:80
			#    interval 30
			#    ip-dscp 0
			#    recv 302
			#    recv-disable none
			#    send "GET /nesp/app/heartbeat HTTP/1.1\r\nHost:hkjh\r\nConnection: close\r\n\r\n"
			#    time-until-up 0
			#    timeout 91
			#}
	return f5_monitors


def explode_serverfarms(serverfarm_dictable, f5_nodes):

	# DICT STRUCT
	#{ pool_name: 'pool_name', pool_lb_method: 'pool_lb_method', pool_monitor: 'pool_monitor'
	#  pool_description: 'pool_description', pool_members:
	#  [ {'node_name': node_name , 'node_ip': node_ip, 'node_description': node_description, 'node_inservice': node_inservice },
	#    {'node_name': node_name , 'node_ip': node_ip, 'node_description': node_description, 'node_inservice': node_inservice },
	#    { .. } ]
	#}

	f5_pool_table=[]
	pool_node_member=""  # temp node_member var
	pool_monitor=""
	pool_lb_method=""
	member_inservice=0
	last_pool_member=""
	for table_item in serverfarm_dictable:
		if DEBUG:
			print "server farm data -> "
			print table_item
			print "server farm data -> "
		pool_name=table_item['serverfarm_name']
		pool_data=table_item['serverfarm_data']
		pool_members=[]

		#cleanup
		pool_monitor=""
		pool_lb_method=""
		pool_description=""


		for pool_items in pool_data:

			if re.match(".*probe\s.*", pool_items):
				pool_monitor=get_config_line_part(pool_items,1)
				pool_monitor_found=1

			if re.match(".*predictor\s.*", pool_items):
				pool_lb_method=get_config_line_part(pool_items,1)
				pool_lb_method_found=1

			if re.match(".*description\s.*", pool_items):
				pool_description=pool_items
				pool_description_found=1

			if re.match(".*rserver\s.*", pool_items):
				pool_node_member=(get_config_line_part(pool_items,1))
				# search for member data
				node_dummy=get_node(pool_node_member, f5_nodes)
				if not node_dummy:
						pool_node_member="ERROR, NOT FOUND IN MEMBERS ->" + pool_node_member + "<-"
				else:
						node_ip=node_dummy['node_ip']
						node_description=node_dummy['node_description']
						node_inservice=node_dummy['node_inservice']

						pool_members.append(
						{'node_name': pool_node_member , 'node_ip': node_ip, 'node_description': node_description, 'node_inservice': node_inservice }
						)

						if not last_pool_member:
							last_pool_member=pool_node_member

			#if re.match(".*inservice.*", pool_items):  <<---- BIG BUG.. no inservice processing!!
			#
#				# this is for nodes/rservers
			#	member_inservice=1
				# affect last node
				#tabla -> tabla (item)
				# this pool table
			#	member_data=f5_pool_table.get('pool_name')


		# build dict for this serverfarm/pool

		f5_pool_table.append({ 'pool_name': pool_name, 'pool_lb_method': pool_lb_method, 'pool_monitor': pool_monitor, 'pool_description': pool_description, 'pool_members': pool_members } )

	return f5_pool_table


def get_node(node_to_search, rservers_dict):
	# search on this table:
	# {'node_config': {'node_description': '', 'node_inservice': 1, 'node_ip': '10.58.4.58'}, 'node_name': 'vorindidev-08'}
	# 	node_data=""
	node_data=""
	for table_item in rservers_dict:
		node_name=table_item['node_name']
		if DEBUG:
			print "searching >", node_name, "< against >", node_to_search
		if node_to_search == node_name:
			#this line contains the node data
			node_data=table_item['node_config']
			node_found=1
			#print "<found node>"
			break
	return node_data


def explode_rservers(rservers_dict):
	f5_nodes_table=[]
	for table_item in rservers_dict:
		node_name=table_item['rserver_name']
		if DEBUG:
			print "node name ->", node_name
		node_data=table_item['rserver_data']

		# look for data
		ip_found=0
		node_inservice=0
		node_description=""

		for rserver_items in node_data:
			if re.match(".*ip address.*", rserver_items): # found ip address, extract
				if DEBUG:
					print "found ip ", rserver_items
				node_ip=get_config_line_part(rserver_items,2)
				# get out
				ip_found=1

			if re.match(".*description.*", rserver_items): # found ip address, extract
				if DEBUG:
					print "found description ", rserver_items
				node_description=rserver_items # <--- SEARCH and replace "description" BUG
				# get out
				node_description_found=1

			if re.match(".*inservice.*", rserver_items):
				if DEBUG:
					print "found inservice ", rserver_items
				node_inservice=1

		if ip_found == 1:
			if DEBUG:
				print "node ip found", node_ip
		else:
			print "bug ??? no node ip found, is this right ?"
			print "nodo que genero el error : ", node_name
			exit(1)

		# construct nodes
		# ltm node /Common/10.56.74.210 {
        #       address 10.56.74.210
		#

		# crear un construct con los datos necesarios para regenerarlo
		f5_node_dict= {'node_ip': node_ip, 'node_description': node_description, 'node_inservice': node_inservice }
		f5_pool_dict= {'node_name': node_name , 'node_config': f5_node_dict }

		f5_nodes_table.append(f5_pool_dict)

		if DEBUG:
			print "<--- -nodes "
			dump_table(f5_nodes_table)

	return f5_nodes_table
	# returns this table:
	# {'node_config': {'node_description': '', 'node_inservice': 1, 'node_ip': '10.58.4.58'}, 'node_name': 'vorindidev-08'}


def get_config_line_part(config_line, field):
	#print "------"
	#print "will get >" , config_line, "< field", field
	temp_table = config_line.split()
	return_data=temp_table[field]
	return return_data


def get_section2(expreg):
	"buscar lineas que coincidan con regexp y hasta que se rompa la indentacion"
	global file_content
	section=list()

	sw_section_found=0

	# search for starting 'section'
	for line in file_content:
		found=re.match(expreg, line)

		if found:
			if DEBUG:
				print "found ", line
				print "looking for data..."
			section.append(line)
			sw_section_found=1
			continue

		if sw_section_found == 1:
			# the line don't begins with space or its empty
			beg_line=re.search('^[^\s\s]', line)
			# test that the line is not empty or has something in the begining that don't match
			if line.isspace() or beg_line and not found:
				# THIS IS OVER
				if DEBUG:
					print "THIS IS OVER line is >", line
				break
			else:
				#keep storing on data until a next probe is found
				if DEBUG:
					print "found data from probe >", line, "<"
				section.append(line)

	return section

def get_section(expreg):
	"buscar lineas que coincidan con regexp y hasta que se rompa la indentacion"
	global file_content
	section=list()

	sw_section_found=0

	# search for starting 'section'
	for line in file_content:
		found=re.match(expreg, line)

		if found:
			if DEBUG:
				print "found ", line
				print "looking for data..."
			section.append(line)
			sw_section_found=1
			continue

		if sw_section_found == 1:
			# the line don't begins with space or its empty
			beg_line=re.search('^[^\s\s]', line)
			# test that the line is not empty or has something in the begining that don't match
			if line.isspace() or beg_line and not found:
				# THIS IS OVER
				if DEBUG:
					print "THIS IS OVER line is >", line
				break
			else:
				#keep storing on data until a next probe is found
				if DEBUG:
					print "found data from probe >", line, "<"
				section.append(line)

	return section


def dissect_again(table_to_dissect):
	"hardcoded for policy_map_multi"

	# create plain table
	# lstrip spaces when 'class' found
	# process new table with normal dissect
	return_table=[]
	table_items=[]

	for items in table_to_dissect:
		if DEBUG:
			print "testing out loop>", items

		table_item=items.get('policy_map_multi_data')
		if DEBUG:
			print "table_items_value", table_item
		for new_table_item in table_item:
			#print "testing inner loop>", new_table_item
			if re.match("^\s.*class", new_table_item):
				new_value=new_table_item.lstrip()
				new_table_item=new_value
			return_table.append(new_table_item)

	if DEBUG:
		print "table contents"
		for items in return_table:
			print items
		#print "value : %s " % table_item
		#for keys, values in items:
		#	print (keys)
		#	print (values)

	return return_table

#
# DISSECT ROUTINES
#

def dissect_section(section_regexp, section_raw,section_dict,section_id):
	"almacenar secciones en listas"

	if DEBUG:
		print "section_regexp : >", section_regexp
		print "section raw: >", section_raw
		print "section dict: >", section_dict
		print "section id: >", section_id


	if len(section_raw) == 0:
		print "seccion vacia, no se encuentra la expresion ", section_regexp
		section_return=[]
		return(section_return)
		#exit(1)

	sw_section_found=0
	section_counter=0
	section_return=list()
	section_split=list()
	section_data=list()
	section_name=""
	section_protocol=""
	saved_section_dict=dict(section_dict)

	# search for starting 'probe'
	for line in section_raw:
		found=re.match(section_regexp, line)

		if DEBUG:
			print "loop section dict ->", section_dict

		if found:
			if sw_section_found:
				# full probe

				section_variable_list=list()

				section_dict[data_section_name]=section_data

				if DEBUG:
					print "section dict ->", section_dict
					print "stored section >", section_dict[section_id]
				section_return.append(dict(section_dict))
				# clear section_data
				section_dict=dict(saved_section_dict)
				if DEBUG:
					print "restored dic"
					print "section dict ->", section_dict
					print "section return -> ", section_return
					print "-----"
					print len(section_return)
				section_data=list()
				sw_section_found=1


			section_dict=dict(saved_section_dict)
			if DEBUG:
				print "found ", line
				print "looking for data..."

			sw_section_found=1

			for key, value in section_dict.iteritems():
				section_name=key
				field_option=value
				if field_option == 0:
					data_section_name=section_name
				else:
					#
					section_split=list()
					section_split=line.split()
					if DEBUG:
						print "section name ->", section_name
						print "field_option ->", value

					section_dict[section_name]=section_split[field_option]
					section_counter=section_counter+1
			continue

		if sw_section_found == 1:
			# test that the line is not empty
			if line.isspace():
				# THIS IS OVER
				if DEBUG:
					print "THIS IS OVER line is >", line
					print "stored section >", section_name

				section_dict[data_section_name]=section_data
				section_return.append(dict(section_dict))

				if DEBUG:
					print len(section_return)
					print "Getting out"

				section_data=list()
				break
			else:
				#keep storing on data until a next probe is found
				if DEBUG:
					print "found data from section >", line

				section_data.append(line)

	#flush buffer
	section_dict[data_section_name]=section_data

	if DEBUG:
		print "section dict ->", section_dict
		print "stored section >", section_dict[section_id]

	section_return.append(dict(section_dict))

	if DEBUG:
		if len(section_return) > 0:
			print "DUMPCLEAN --------"
			print section_return
			print "DUMPCLEAN --------"
		else:
			print "section empty"

	return section_return

#
# CONFIG FILE LOAD ROUTINES
#
def read_file(inputfile):
	"esto carga el archivo a una lista"
	global file_content
	file_content = [line.rstrip('\n') for line in open(inputfile)]


#
# MISC ARRAY MEMORY ROUTINES
#
def dump_table(table):
	for items in table:
		print items

def dumpclean(obj):
	if type(obj) == dict:
		for k, v in obj.items():
			if hasattr(v, '__iter__'):
				print "key ->", k
				dumpclean(v)
			else:
				print '%s : %s' % (k, v)
	elif type(obj) == list:
		for v in obj:
			if hasattr(v, '__iter__'):
				dumpclean(v)
			else:
				print "value ->", v
	else:
		print obj


#
# MAIN
#

if __name__ == "__main__":
	main(sys.argv[1:])



