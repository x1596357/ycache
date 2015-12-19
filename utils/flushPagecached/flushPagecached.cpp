#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <chrono>
#include <thread>

using namespace std;

bool isCpuUnderBound(int cpuBound);
bool isMemUnderBound(long long memBound);

// This program flush page cache every argv[1] seconds
// if CPU usage is under argv[2]% and free memory(totally free)+buffer is below
// argv[3] kbytes
// For example:
// ./flushPagecached 30 50 40960 &
// if no arguments follow the program, by default, this program
// flush pagecache every 30 seconds if CPU usage is under 50% and free memory
// +buffer is below 40960 KiB
int main(int argc, char const *argv[])
{
	int interval = 30;
	int cpuBound = 50;
	long long memBound = 40960;

	const char *drop_caches_path = "/proc/sys/vm/drop_caches";
	ofstream drop_caches;

	if (argc != 1 && argc != 4) {
		cout << "Usage:" << argv[0]
		     << " INTERVAL(1~INT_MAX) CPU_BOUND(0~100) "
			"MEM_BOUND(1~LLONG_MAX, in kbytes)"
		     << endl;
		cout << "For example:" << endl;
		cout << "./" << argv[0] << " 30 50 40960 &" << endl;
		return -1;
	}

	if (argc == 4) {
		interval = atoi(argv[1]);
		cpuBound = atoi(argv[2]);
		memBound = atoll(argv[3]);

		if (interval < 1) {
			cout << "Invalid interval: use default 30s" << endl;
		}
		if (cpuBound < 0 || cpuBound > 100) {
			cout << "Invalid cpu upper bound: use default 50" << '%'
			     << endl;
		}
		if (memBound < 1) {
			cout << "Invalid memBound: use default 40960 KiB"
			     << endl;
		}
	}

	cout << "Flush interval:" << interval << "s" << endl;
	cout << "CPU upper bound:" << cpuBound << '%' << endl;
	cout << "Memory bound:" << memBound << "KiB" << endl << endl;

	while (true) {
		drop_caches.open(drop_caches_path);
		if (!drop_caches) {
			cerr << "Unable to open " << drop_caches_path << endl;
			cerr << "Check if you have permission, you should have "
				"root"
			     << endl;
			return -2;
		}
		if (isCpuUnderBound(cpuBound) && isMemUnderBound(memBound)) {
			drop_caches << 1 << endl;
			cout << "Condition statisfied, dropping caches ..."
			     << endl;
		}
		drop_caches.close();
		// Checking cpu usage needs 1 second
		int remainInterval = interval - 1;
		if (remainInterval > 0)
			this_thread::sleep_for(
			    std::chrono::seconds(remainInterval));
	}

	return 0;
}

// Check if CPU usage in 1 second is below cpuBound
bool isCpuUnderBound(int cpuBound)
{
	char cpu_name[128];
	long long user, nice, sys, idle, iowait, irq, softirq;
	long long cpuIdle;
	long long cpuTotal;

	const char *proc_stat = "/proc/stat";
	ifstream stat(proc_stat);
	stat >> cpu_name >> user >> nice >> sys >> idle >> iowait >> irq >>
	    softirq;
	// cout << cpu_name << ' ' << user << ' ' << nice << ' ' << sys << ' '
	//     << idle << ' ' << iowait << ' ' << irq << ' ' << softirq << endl;
	/* No iowait */
	cpuTotal = user + nice + sys + idle + irq + softirq;
	cpuIdle = idle;
	this_thread::sleep_for(std::chrono::seconds(1));
	stat.seekg(0, ios::beg);
	stat >> cpu_name >> user >> nice >> sys >> idle >> iowait >> irq >>
	    softirq;
	// cout << cpu_name << ' ' << user << ' ' << nice << ' ' << sys << ' '
	//     << idle << ' ' << iowait << ' ' << irq << ' ' << softirq << endl;
	cpuTotal = user + nice + sys + idle + irq + softirq - cpuTotal;
	cpuIdle = idle - cpuIdle;

	long long cpuUsage = 100 * (cpuTotal - cpuIdle) / cpuTotal;
	cout << "CPU usage:" << cpuUsage << '%' << endl;

	if (cpuUsage <= cpuBound)
		return true;
	else
		return false;
}

// Check if free memory(as in not used by anything, even page cache)
// plus buffer is below memBound
bool isMemUnderBound(long long memBound)
{
	string line;
	char tmp_string[128];
	long long freeKb;
	long long bufferKb;

	const char *proc_meminfo = "/proc/meminfo";
	ifstream meminfo(proc_meminfo);
	/* this is used to consume the first line */
	getline(meminfo, line);
	/* get actual free memory in kbytes */
	getline(meminfo, line);
	istringstream issFreeKb(line);
	issFreeKb >> tmp_string >> freeKb;
	cout << "Free memory:" << freeKb << "KiB" << endl;
	/* this is used to consume the third line */
	getline(meminfo, line);
	/* get actual buffer in kbytes  */
	getline(meminfo, line);
	istringstream issBufferKb(line);
	issBufferKb >> tmp_string >> bufferKb;
	cout << "Buffer:" << bufferKb << "KiB" << endl << endl;

	if (freeKb + bufferKb < memBound)
		return true;
	else
		return false;
}