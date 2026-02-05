
""" itk.py
Entry Point for the ICS Tool Kit (ITK) CLI and main CLI Driver
Unified interface: scan, read, write, info
"""

import click
import signal
import sys
import logging
from rich.console import Console
from core.output import print_banner, status, print_table
from core.session import session_manager

logging.basicConfig(level=logging.CRITICAL)
logging.getLogger("snap7").setLevel(logging.CRITICAL)

def handle_sigint(_sig, _frame):  # pylint: disable=invalid-name
    """
    Handle SIGINT signal
    """
    print("\nReceived SIGINT. Exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)


console = Console()

# ============================================================================
# USAGE EXAMPLES - Shown on incorrect usage to teach new players
# ============================================================================

MODBUS_EXAMPLES = """
[bold cyan]Modbus Examples:[/bold cyan]
  [dim]Types: coil (1-bit R/W), discrete (1-bit RO), input (16-bit RO), holding (16-bit R/W)[/dim]
  
  [green]Scan all registers:[/green]
    itk -t 192.168.1.10 modbus scan

  [green]Scan all slaves:[/green]
    itk -t 192.168.1.10 modbus scan --slaves
  
  [green]Read holding register 100:[/green]
    itk -t 192.168.1.10 modbus read 100 holding
  
  [green]Write 1234 to holding register 100:[/green]
    itk -t 192.168.1.10 modbus write 100 holding 1234
  
  [green]Read coil 0:[/green]
    itk -t 192.168.1.10 modbus read 0 coil
    
  [green]Custom port:[/green]
    itk -t 192.168.1.10 -p 5020 modbus scan
"""


S7_EXAMPLES = """
[bold cyan]S7comm Examples:[/bold cyan]
  [green]Deep Scan (Enumerates TSAPs 0x100-0x200):[/green]
    itk -t 192.168.1.10 s7 scan --aggressive

  [green]Read DB1 offset 0:[/green]
    itk -t 192.168.1.10 s7 read 1.0 db

  [green]Write byte:[/green]
    itk -t 192.168.1.10 s7 write 1.0 db 255
"""

BACNET_EXAMPLES = """
[bold cyan]BACnet Examples:[/bold cyan]
  [dim]Types: analog_input, analog_output, analog_value,[/dim]
  [dim]       binary_input, binary_output, binary_value[/dim]
  
  [green]Discover all devices and objects:[/green]
    itk -t 192.168.1.10 bacnet scan
  
  [green]Read binary output 1 (e.g., Door Lock):[/green]
    itk -t 192.168.1.10 bacnet read 1 binary_output
  
  [green]Write ON to binary output 1:[/green]
    itk -t 192.168.1.10 bacnet write 1 binary_output ON
  
  [green]Read analog value 2 (e.g., Temperature):[/green]
    itk -t 192.168.1.10 bacnet read 2 analog_value
    
  [green]Custom port:[/green]
    itk -t 192.168.1.10 -p 47809 bacnet scan
"""

ENIP_EXAMPLES = """
[bold cyan]EtherNet/IP Examples:[/bold cyan]
  [dim]Types: tag[/dim]
  
  [green]Enumerate all tags:[/green]
    itk -t 192.168.1.10 enip scan
  
  [green]Read tag named 'FLAG':[/green]
    itk -t 192.168.1.10 enip read FLAG tag
  
  [green]Write to tag 'STATUS':[/green]
    itk -t 192.168.1.10 enip write STATUS tag 1
  
  [green]Get device identity:[/green]
    itk -t 192.168.1.10 enip info
    
  [green]Custom port:[/green]
    itk -t 192.168.1.10 -p 44819 enip scan
"""


def show_examples(protocol: str):
    """Show protocol-specific usage examples."""
    examples = {
        "modbus": MODBUS_EXAMPLES,
        "s7": S7_EXAMPLES,
        "bacnet": BACNET_EXAMPLES,
        "enip": ENIP_EXAMPLES,
    }
    if protocol in examples:
        console.print(examples[protocol])


# ============================================================================
# MAIN CLI GROUP
# ============================================================================

@click.group()
@click.option('--target', '-t', required=True, help="Target IP address")
@click.option('--port', '-p', type=int, help="Target port (uses protocol default if not specified)")
@click.option('--timeout', '-T', type=int, default=5, help="Connection timeout in seconds")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbose output")
@click.option('--json', '-j', 'use_json', is_flag=True, help="Output results as JSON")
@click.pass_context
def cli(ctx, target, port, timeout, verbose, use_json):
    """ITK: The ICS Tool Kit for CTFs and Auditing."""
    ctx.ensure_object(dict)
    ctx.obj['TARGET'] = target
    ctx.obj['PORT'] = port
    ctx.obj['TIMEOUT'] = timeout
    ctx.obj['VERBOSE'] = verbose
    ctx.obj['JSON'] = use_json
    ctx.obj['SESSION'] = session_manager

    if not use_json:
        print_banner()
        status(f"Target: {target}" + (f":{port}" if port else ""), "info")


# ============================================================================
# UTILITY COMMANDS
# ============================================================================

@cli.command()
@click.pass_context
def sessions(ctx):
    """List cached sessions."""
    all_sessions = ctx.obj['SESSION'].list_sessions()
    if not all_sessions:
        status("No active sessions", "info")
        return
    if ctx.obj['JSON']:
        import json
        console.print(json.dumps(all_sessions, indent=2))
    else:
        print_table(
            "Cached Sessions",
            ["Target", "Protocol", "Last Used"],
            [[s['target'], s['protocol'], s['last_used']] for s in all_sessions]
        )


@cli.command()
@click.pass_context
def clear_sessions(ctx):
    """Clear all cached sessions."""
    ctx.obj['SESSION'].clear()
    status("All sessions cleared", "success")


@cli.command()
@click.pass_context
def identify(ctx):
    """Identify the ICS protocol running on target:port."""
    from core.identify import identify_protocol
    import json as json_lib

    port = ctx.obj['PORT']
    if not port:
        status("Port is required for identify (use -p)", "error")
        return

    status(f"Probing {ctx.obj['TARGET']}:{port}...", "info")
    result = identify_protocol(ctx.obj['TARGET'], port, ctx.obj['TIMEOUT'])
    
    if result:
        if ctx.obj['JSON']:
            console.print(json_lib.dumps({
                "target": ctx.obj['TARGET'],
                "port": port,
                "protocol": result.protocol,
                "confidence": result.confidence,
                "details": result.details
            }, indent=2))
        else:
            status(f"Protocol: {result.protocol.upper()}", "success")
            status(f"Confidence: {result.confidence}", "info")
            status(f"Details: {result.details}", "info")
    else:
        if ctx.obj['JSON']:
            console.print(json_lib.dumps({
                "target": ctx.obj['TARGET'],
                "port": port,
                "protocol": None,
                "error": "No protocol identified"
            }, indent=2))
        else:
            status("Server may be offline or running an unknown protocol", "warning")


# ============================================================================
# MODBUS
# ============================================================================

@cli.group(invoke_without_command=True)
@click.pass_context
def modbus(ctx):
    """Modbus TCP: Register enumeration and manipulation."""
    ctx.obj['PROTOCOL'] = 'modbus'
    ctx.obj['PORT'] = ctx.obj['PORT'] or 502
    if ctx.invoked_subcommand is None:
        show_examples("modbus")


@modbus.command('scan')
@click.option('--unit', '-u', type=int, default=1, help="Modbus slave/unit ID")
@click.option('--range-start', '-s', type=int, default=0, help="Start address")
@click.option('--range-end', '-e', type=int, default=100, help="End address")
@click.option('--slaves', is_flag=True, help="Scan for active slave IDs instead of registers")
@click.pass_context
def modbus_scan(ctx, unit, range_start, range_end, slaves):
    """Enumerate registers or discover active slave IDs."""
    from protocols.modbus import ModbusProtocol
    from core.output import print_result
    
    protocol = ModbusProtocol(
        target=ctx.obj['TARGET'],
        port=ctx.obj['PORT'],
        timeout=ctx.obj['TIMEOUT'],
        unit_id=unit
    )
    
    conn_result = protocol.connect()
    if not conn_result.success:
        print_result(conn_result, ctx.obj['JSON'])
        return
    
    status(f"Connected to {ctx.obj['TARGET']}:{ctx.obj['PORT']}", "success")
    
    if slaves:
        status("Scanning for active slave IDs (this may take a while)...", "info")
        result = protocol.scan_slaves(range(1, 100)) 
    else:
        status(f"Scanning unit {unit}, addresses {range_start}-{range_end}...", "info")
        result = protocol.scan(range_start, range_end)
    
    protocol.close()
    
    if ctx.obj['JSON']:
        print_result(result, use_json=True)
    else:
        if result.success:
            if slaves:
                status(f"Found {result.data['count']} active slaves: {result.data['active_slaves']}", "success")
            else:
                status(f"Found {result.data['found']} non-zero registers", "success")
                if result.data['registers']:
                    print_table(
                        f"Modbus Registers (Unit {unit})",
                        ["Address", "Type", "Value"],
                        [[r['address'], r['type'], r['value']] for r in result.data['registers']]
                    )
        else:
            print_result(result, use_json=False)


@modbus.command('read')
@click.argument('address', type=int)
@click.argument('type', type=click.Choice(['coil', 'discrete', 'input', 'holding']))
@click.option('--unit', '-u', type=int, default=1, help="Modbus slave/unit ID")
@click.option('--count', '-c', type=int, default=1, help="Number of registers to read")
@click.pass_context
def modbus_read(ctx, address, type, unit, count):
    """Read registers. Usage: read <ADDRESS> <TYPE>"""
    from protocols.modbus import ModbusProtocol
    from core.output import print_result
    
    protocol = ModbusProtocol(
        target=ctx.obj['TARGET'],
        port=ctx.obj['PORT'],
        timeout=ctx.obj['TIMEOUT'],
        unit_id=unit
    )
    
    conn_result = protocol.connect()
    if not conn_result.success:
        print_result(conn_result, ctx.obj['JSON'])
        return
    
    result = protocol.read(address, type, count)
    protocol.close()
    
    if ctx.obj['JSON']:
        print_result(result, use_json=True)
    else:
        if result.success:
            values = result.data['values']
            if count == 1:
                status(f"{type.upper()} {address} = {values[0]}", "success")
            else:
                status(f"{type.upper()} {address}-{address+count-1}:", "success")
                for i, v in enumerate(values):
                    console.print(f"  [{address+i}] = {v}")
        else:
            print_result(result, use_json=False)


@modbus.command('write')
@click.argument('address', type=int)
@click.argument('type', type=click.Choice(['coil', 'holding']))
@click.argument('value', type=int)
@click.option('--unit', '-u', type=int, default=1, help="Modbus slave/unit ID")
@click.pass_context
def modbus_write(ctx, address, type, value, unit):
    """Write to a register. Usage: write <ADDRESS> <TYPE> <VALUE>"""
    from protocols.modbus import ModbusProtocol
    from core.output import print_result
    
    protocol = ModbusProtocol(
        target=ctx.obj['TARGET'],
        port=ctx.obj['PORT'],
        timeout=ctx.obj['TIMEOUT'],
        unit_id=unit
    )
    
    conn_result = protocol.connect()
    if not conn_result.success:
        print_result(conn_result, ctx.obj['JSON'])
        return
    
    result = protocol.write(address, value, type)
    protocol.close()
    
    if ctx.obj['JSON']:
        print_result(result, use_json=True)
    else:
        if result.success:
            status(f"Wrote {value} to {type.upper()} {address}", "success")
        else:
            print_result(result, use_json=False)


# ============================================================================
# S7COMM
# ============================================================================

@cli.group(invoke_without_command=True)
@click.pass_context
def s7(ctx):
    """S7comm: Data Block access and CPU control."""
    ctx.obj['PROTOCOL'] = 's7'
    ctx.obj['PORT'] = ctx.obj['PORT'] or 102
    if ctx.invoked_subcommand is None:
        pass 

@s7.command('scan')
@click.option('--rack', '-r', type=int, default=0, help="PLC Rack Number")
@click.option('--slot', '-s', type=int, default=2, help="PLC Slot Number")
@click.option('--aggressive', '-A', is_flag=True, help="Brute-force TSAPs (Like s7scan.py)")
@click.pass_context
def s7_scan(ctx, rack, slot, aggressive):
    """Scan S7 device. Default: Connects to Rack/Slot. Aggressive: Scans TSAPs."""
    from protocols.s7comm import S7Protocol
    from core.output import print_result
    
    if aggressive:
        status(f"Starting Aggressive TSAP Scan on {ctx.obj['TARGET']}...", "info")
        result = S7Protocol.scan_network(
            target=ctx.obj['TARGET'],
            port=ctx.obj['PORT'],
            timeout=ctx.obj['TIMEOUT']
        )
        
        if ctx.obj['JSON']:
            print_result(result, use_json=True)
            return

        modules = result.data.get("modules", [])
        if not modules:
            status("No valid TSAPs found.", "warning")
            return

        status(f"Found {len(modules)} potential TSAP(s).", "success")
        
        for mod in modules:
            tsap = mod['tsap']
            l_tsap = mod['local_tsap']
            state = mod['cpu_state']
            conn_stat = mod['status']
            info = mod['info']
            
            console.print(f"\n[bold green]== Match: Remote {tsap} | Local {l_tsap} ==[/bold green]")
            console.print(f"  [dim]Connection Status:[/dim] {conn_stat}")
            
            if "Partial" in conn_stat:
                console.print("  [yellow]Note: Handshake incomplete (Bad PDU). TSAP is valid but S7-Layer failed.[/yellow]")
                continue

            console.print(f"  [dim]CPU State:[/dim] {state}")
            
            # 1. Component ID
            comps = info.get("component_identification", [])
            if comps:
                print_table(f"Component ID", ["Index", "Value"], [[c['index'], c['value']] for c in comps])

            # 2. Module ID
            mod_ids = info.get("module_identification", [])
            if mod_ids:
                print_table(f"Module ID", ["Index", "Data"], [[m['index'], m['ascii']] for m in mod_ids])
            
            # 3. Protection
            prot = info.get("protection", {})
            if prot:
                console.print(f"  [bold]Protection Level:[/bold] {prot.get('level', 'Unknown')}")

        return

    # Standard Scan
    protocol = S7Protocol(
        target=ctx.obj['TARGET'],
        port=ctx.obj['PORT'],
        timeout=ctx.obj['TIMEOUT'],
        rack=rack,
        slot=slot
    )
    
    conn = protocol.connect()
    if not conn.success:
        status("Connection failed. Try --aggressive to brute force TSAPs.", "error")
        return

    status(f"Connected to Rack {rack}, Slot {slot}", "success")
    result = protocol.scan()
    protocol.close()
    
    if ctx.obj['JSON']:
        print_result(result, use_json=True)
    else:
        dbs = result.data.get("found_dbs", [])
        status(f"Found DBs: {dbs}", "success")
        info = result.data.get("info", {})
        if info.get("component_identification"):
             console.print(f"  [dim]System: {info['component_identification'][0]['value']}[/dim]")

@s7.command('read')
@click.argument('address')
@click.argument('type', type=click.Choice(['db', 'input', 'output', 'marker']), default='db')
@click.option('--size', type=int, default=1)
@click.pass_context
def s7_read(ctx, address, type, size):
    """ Reads a target rack and slot """
    from protocols.s7comm import S7Protocol
    from core.output import print_result
    proto = S7Protocol(ctx.obj['TARGET'], ctx.obj['PORT'], ctx.obj['TIMEOUT'])
    if proto.connect().success:
        res = proto.read(address, type, size)
        proto.close()
        if ctx.obj['JSON']: print_result(res, True)
        else:
            if res.success: status(f"READ {address}: {res.data['hex']} ({res.data['ascii']})", "success")
            else: status(res.error, "error")

@s7.command('write')
@click.argument('address')
@click.argument('value', type=int)
@click.argument('type', type=click.Choice(['db', 'output', 'marker']), default='db')
@click.pass_context
def s7_write(ctx, address, value, type):
    """ Writes to a target format in a desingated slot and rack """
    from protocols.s7comm import S7Protocol
    from core.output import print_result
    proto = S7Protocol(ctx.obj['TARGET'], ctx.obj['PORT'], ctx.obj['TIMEOUT'])
    if proto.connect().success:
        res = proto.write(address, value, type)
        proto.close()
        if ctx.obj['JSON']: print_result(res, True)
        else:
            if res.success: status("Write successful", "success")
            else: status(res.error, "error")


# ============================================================================
# BACNET
# ============================================================================

@cli.group(invoke_without_command=True)
@click.pass_context
def bacnet(ctx):
    """BACnet/IP: Building Automation discovery and control."""
    ctx.obj['PROTOCOL'] = 'bacnet'
    ctx.obj['PORT'] = ctx.obj['PORT'] or 47808
    if ctx.invoked_subcommand is None:
        show_examples("bacnet")


@bacnet.command('scan')
@click.pass_context
def bacnet_scan(ctx):
    """Discover devices and enumerate objects (Who-Is)."""
    status(f"Scanning BACnet at {ctx.obj['TARGET']}:{ctx.obj['PORT']}...", "info")
    # TODO: Implement BACnet scan
    status("Not implemented - See Phase 3", "warning")


@bacnet.command('read')
@click.argument('object_id', type=int)
@click.argument('type', type=click.Choice([
    'analog_input', 'analog_output', 'analog_value',
    'binary_input', 'binary_output', 'binary_value'
]))
@click.pass_context
def bacnet_read(ctx, object_id, type):
    """Read object value. Usage: read <OBJECT_ID> <TYPE>"""
    status(f"Reading {type} object {object_id}...", "info")
    # TODO: Implement BACnet read
    status("Not implemented - See Phase 3", "warning")


@bacnet.command('write')
@click.argument('object_id', type=int)
@click.argument('type', type=click.Choice([
    'analog_output', 'analog_value', 'binary_output', 'binary_value'
]))
@click.argument('value')
@click.pass_context
def bacnet_write(ctx, object_id, type, value):
    """Write object value. Usage: write <OBJECT_ID> <TYPE> <VALUE>"""
    # Convert ON/OFF for binary types
    if type.startswith('binary'):
        if value.upper() in ('ON', 'TRUE', '1'):
            value = 'active'
        elif value.upper() in ('OFF', 'FALSE', '0'):
            value = 'inactive'
    status(f"Writing {value} to {type} object {object_id}...", "info")
    # TODO: Implement BACnet write
    status("Not implemented - See Phase 3", "warning")


# ============================================================================
# ETHERNET/IP
# ============================================================================

@cli.group(invoke_without_command=True)
@click.pass_context
def ethip(ctx):
    """EtherNet/IP: Tag browsing and manipulation."""
    ctx.obj['PROTOCOL'] = 'enip'
    ctx.obj['PORT'] = ctx.obj['PORT'] or 44818
    if ctx.invoked_subcommand is None:
        show_examples("enip")


@ethip.command('scan')
@click.pass_context
def ethip_scan(ctx):
    """Enumerate all tags."""
    from protocols.EthIP import EthIP
    from core.output import print_result

    status(f"Scanning EtherNet/IP at {ctx.obj['TARGET']}:{ctx.obj['PORT']}...", "info")
    
    proto = EthIP(ctx.obj['TARGET'], ctx.obj['PORT'], ctx.obj['TIMEOUT'])
    result = proto.scan()
    
    if ctx.obj['JSON']:
        print_result(result, use_json=True)
    else:
        if result.success:
            identities = result.data.get('identities', [])
            status(f"Found {len(identities)} identity item(s)", "success")
            for id_item in identities:
                console.print(f"  [bold]Product:[/bold] {id_item.get('product_name')}")
                console.print(f"  Vendor: {id_item.get('vendor_id')} | Device Type: {id_item.get('device_type')}")
                console.print(f"  Serial: {id_item.get('serial')} | Code: {id_item.get('product_code')}")
        else:
            print_result(result, use_json=False)


@ethip.command('read')
@click.argument('tag_name')
@click.argument('type', type=click.Choice(['tag']))
@click.pass_context
def ethip_read(ctx, tag_name, type):
    """Read a tag. Usage: read <TAG_NAME> tag"""
    from protocols.EthIP import EthIP
    from core.output import print_result

    status(f"Reading tag '{tag_name}'...", "info")
    proto = EthIP(ctx.obj['TARGET'], ctx.obj['PORT'], ctx.obj['TIMEOUT'])
    
    if proto.connect().success:
        res = proto.read(tag_name)
        proto.close()
        if ctx.obj['JSON']: print_result(res, use_json=True)
        else:
            if res.success: status(f"{tag_name}: {res.data}", "success")
            else: status(res.error, "error")
    else:
        status("Connection failed", "error")


@ethip.command('write')
@click.argument('tag_name')
@click.argument('type', type=click.Choice(['tag']))
@click.argument('value')
@click.pass_context
def ethip_write(ctx, tag_name, type, value):
    """Write to a tag. Usage: write <TAG_NAME> tag <VALUE>"""
    from protocols.EthIP import EthIP
    from core.output import print_result

    status(f"Writing '{value}' to tag '{tag_name}'...", "info")
    proto = EthIP(ctx.obj['TARGET'], ctx.obj['PORT'], ctx.obj['TIMEOUT'])
    
    if proto.connect().success:
        res = proto.write(tag_name, value)
        proto.close()
        if ctx.obj['JSON']: print_result(res, use_json=True)
        else:
            if res.success: status("Write successful", "success")
            else: status(res.error, "error")
    else:
        status("Connection failed", "error")


@ethip.command('info')
@click.pass_context
def ethip_info(ctx):
    """Get device identity."""
    from protocols.EthIP import EthIP
    from core.output import print_result

    status(f"Getting EtherNet/IP identity from {ctx.obj['TARGET']}...", "info")
    proto = EthIP(ctx.obj['TARGET'], ctx.obj['PORT'], ctx.obj['TIMEOUT'])
    result = proto.get_info()
    
    if ctx.obj['JSON']:
        print_result(result, use_json=True)
    else:
        if result.success:
            # Re-use scan logic for display as get_info returns same structure in our impl
            identities = result.data.get('identities', [])
            if identities:
                id_item = identities[0]
                status(f"Device: {id_item.get('product_name')}", "success")
                console.print(f"  Vendor ID: {id_item.get('vendor_id')}")
                console.print(f"  Serial: {id_item.get('serial')}")
            else:
                status("No identity information found.", "warning")
        else:
            print_result(result, use_json=False)


# ============================================================================
# CUSTOM / BLACKBOX
# ============================================================================

@cli.group()
@click.pass_context
def custom(ctx):
    """Custom protocol handler for CTF challenges."""
    ctx.obj['PROTOCOL'] = 'custom'


if __name__ == '__main__':
    signal.signal(signal.SIGINT, handle_sigint)
    cli(obj={})