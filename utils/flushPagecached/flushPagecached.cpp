#include <iostream>
#include <fstream>
#include <cstdlib>
#include <chrono>
#include <thread>

using namespace std;

bool isCpuUnderBound(int cpuBound);

// This program flush page cache every argv[1] seconds
// if CPU usage is under argv[2]%
// For example:
// ./flushPagecached 30 50 &
// if no arguments follow the program, by default, this program
// flush pagecache every 30 seconds if CPU usage is under 50%
int main(int argc, char const *argv[])
{
	int interval = 30;
	int cpuBound = 50;
	if (argc != 1 && argc != 3) {
		cout << "Usage:" << argv[0]
		     << " INTERVAL(1~INT_MAX) CPU_BOUND(0~100)" << endl;
		cout << "For example:" << endl;
		cout << "./" << argv[0] << " 30 50 &" << endl;
	}

	if (argc == 3) {
		interval = atoi(argv[1]);
		cpuBound = atoi(argv[2]);

		if (interval < 1) {
			cout << "Invalid interval: use default 30s" << endl;
		}
		cout << "flush interval:" << interval << "s" << endl;
		if (cpuBound < 0 || cpuBound > 100) {
			cout << "Invalid cpu upper bound: use default 50" << '%'
			     << endl;
		}
		cout << "cpu upper bound:" << cpuBound << '%' << endl;
	}

	const char *file_path = "/proc/sys/vm/drop_caches";
	ofstream drop_caches_f(file_path);
	if (!drop_caches_f) {
		cerr << "Unable to open " << file_path << endl;
		cerr << "Check if you have permission, you should have root"
		     << endl;
		exit(-1);
	}

	while (true) {
		drop_caches_f.seekg(0, ios::beg);
		if (isCpuUnderBound(cpuBound))
			drop_caches_f << 1 << endl;
		// Checking cpu usage needs 1 second
		std::this_thread::sleep_for(std::chrono::seconds(interval - 1));
	}

	return 0;
}

// Check if CPU usage in 1 second is below cpuBound
bool isCpuUnderBound(int cpuBound)
{
	char cpu_name[128];
	long int user, nice, sys, idle, iowait, irq, softirq;
	long int cpuIdle;
	long long int cpuTotal;

	const char *proc_stat = "/proc/stat";
	ifstream stat(proc_stat);
	stat >> cpu_name >> user >> nice >> sys >> idle >> iowait >> irq >>
	    softirq;
	// cout << cpu_name << ' ' << user << ' ' << nice << ' ' << sys << ' '
	//     << idle << ' ' << iowait << ' ' << irq << ' ' << softirq << endl;
	cpuTotal = user + nice + sys + idle + iowait + irq + softirq;
	cpuIdle = idle;
	std::this_thread::sleep_for(std::chrono::seconds(1));
	stat.seekg(0, ios::beg);
	stat >> cpu_name >> user >> nice >> sys >> idle >> iowait >> irq >>
	    softirq;
	// cout << cpu_name << ' ' << user << ' ' << nice << ' ' << sys << ' '
	//     << idle << ' ' << iowait << ' ' << irq << ' ' << softirq << endl;
	cpuTotal = user + nice + sys + idle + iowait + irq + softirq - cpuTotal;
	cpuIdle = idle - cpuIdle;

	long long int cpuUsage = 100 * (cpuTotal - cpuIdle) / cpuTotal;
	cout << "CPU usage is:" << cpuUsage << '%' << endl;

	if (cpuUsage <= cpuBound)
		return true;
	else
		return false;
}