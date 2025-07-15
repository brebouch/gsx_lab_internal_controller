import psutil

def get_sys_info():
    response = {}
    response.update({'cpu': psutil.cpu_percent(interval=1)})
    memory_info = psutil.virtual_memory()
    response.update({'total_memory':  round(memory_info.total / (1024 ** 3), 2)})
    response.update({'used_memory': round(memory_info.used / (1024 ** 3), 2)})
    response.update({'used_percent_memory': round(memory_info.used / (1024 ** 3), 2)})

    network_stats = psutil.net_io_counters()
    response.update({'bytes_sent':  round(network_stats.bytes_sent / (1024**2), 2)})
    response.update({'bytes_received': round(network_stats.bytes_recv / (1024 ** 2), 2)})
    return response




