#pragma comment(lib, "netapi32.lib")

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <LMaccess.h>
#include <LM.h>
#include <sddl.h>

VOID PrintUsage();
VOID ReplaceAll(std::wstring& str, std::wstring& from, std::wstring& to);
BOOL ResultsToCSV(std::vector <std::map<std::wstring, std::wstring>>& vMapResults, std::wstring& csvFilePath);
VOID EnumLocalGroupMembers(std::vector <std::wstring> vwsArgs);

int wmain(int argc, wchar_t** argv) {
	std::vector <std::wstring> vwsArgs;

	int i = 1;
	while (i < argc) {
		vwsArgs.push_back(argv[i]);
		i++;
	}

	EnumLocalGroupMembers(vwsArgs);

	return 0;
}

VOID PrintUsage() {
	std::wcout << L"Usage: LocalGroupMembers.exe [options] --csv <out file>" << std::endl;
	std::wcout << L"-h\tPrint this usage screen" << std::endl;
	std::wcout << L"-t\tTarget hostname or IP address" << std::endl;
	std::wcout << L"-tL\tFile of line delimited target IPs or hostnames" << std::endl;
	std::wcout << L"-g\tGroup name to enumerate" << std::endl;
	std::wcout << L"--stdout\tDisplay results to stdout. Default if not saving to CSV" << std::endl;
	std::wcout << L"--csv\tCSV file path to store results" << std::endl;
}

VOID ReplaceAll(std::wstring& str, std::wstring& from, std::wstring& to) {
	if (from.empty())
		return;

	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
}

BOOL ResultsToCSV(std::vector <std::map<std::wstring, std::wstring>>& vMapResults, std::wstring& csvFilePath) {
	std::vector <std::wstring> vColumns;
	UINT i = 0;
	UINT j = 0;

	// Open target csv file for writing
	std::wofstream csvFile;
	csvFile.open(csvFilePath);

	// Create column keys from all result keys
	i = 0;
	while (i < vMapResults.size()) {
		for (auto it = vMapResults[i].cbegin(); it != vMapResults[i].cend(); ++it) {
			vColumns.push_back((*it).first);
		}

		// Unique vector here. Idea is to keep memory down
		std::sort(vColumns.begin(), vColumns.end());
		vColumns.erase(std::unique(vColumns.begin(), vColumns.end()), vColumns.end());

		i++;
	}

	// Create/Write column row
	std::wstring columnLine;

	i = 0;
	while (i < vColumns.size() - 1) {
		std::wstring value = vColumns[i];

		// Wrap in double quotes if value contains a comma
		if (value.find(L',') != std::wstring::npos) {
			// RFC-4180, paragraph 7. "If double-quotes are used to enclose fields,
			// then a double-quote appearing inside a field must be escaped by
			// preceding it with another double quote."
			std::wstring from = L"\"";
			std::wstring to = L"\"\"";

			ReplaceAll(value, from, to);

			columnLine += L"\"";
			columnLine += value;
			columnLine += L"\"";
			columnLine += L",";
		}
		else {
			columnLine += value;
			columnLine += L",";
		}

		i++;
	}
	std::wstring value = vColumns[i];

	// Wrap in double quotes if value contains a comma
	if (value.find(L',') != std::wstring::npos) {
		// RFC-4180, paragraph 7. "If double-quotes are used to enclose fields,
		// then a double-quote appearing inside a field must be escaped by
		// preceding it with another double quote."
		std::wstring from = L"\"";
		std::wstring to = L"\"\"";

		ReplaceAll(value, from, to);

		columnLine += L"\"";
		columnLine += value;
		columnLine += L"\"";
	}
	else {
		columnLine += value;
	}

	//std::wcout << columnLine << std::endl;
	csvFile << columnLine << std::endl;

	// Create/Write rows
	i = 0;
	while (i < vMapResults.size()) {
		std::wstring rowLine;

		j = 0;
		while (j < vColumns.size() - 1) {
			try {
				std::wstring value = vMapResults[i].at(vColumns[j]);

				// Wrap in double quotes if value contains a comma
				if (value.find(L',') != std::wstring::npos) {
					// RFC-4180 - paragraph 7 - "If double-quotes are used to enclose fields,
					// then a double-quote appearing inside a field must be escaped by
					// preceding it with another double quote."
					std::wstring from = L"\"";
					std::wstring to = L"\"\"";

					ReplaceAll(value, from, to);

					rowLine += L"\"";
					rowLine += value;
					rowLine += L"\"";
					rowLine += L",";
				}
				else {
					rowLine += value;
					rowLine += L",";
				}
			}
			catch (const std::out_of_range) {
				rowLine += L",";
			}

			j++;
		}
		try {
			std::wstring value = vMapResults[i].at(vColumns[j]);
			if (value.find(',') != std::wstring::npos) {
				// RFC-4180, paragraph "If double-quotes are used to enclose fields,
				// then a double-quote appearing inside a field must be escaped by
				// preceding it with another double quote."
				std::wstring from = L"\"";
				std::wstring to = L"\"\"";

				ReplaceAll(value, from, to);

				rowLine += L"\"";
				rowLine += value;
				rowLine += L"\"";
			}
			else {
				rowLine += value;
			}
		}
		catch (const std::out_of_range) {}

		//std::wcout << rowLine << std::endl;
		csvFile << rowLine << std::endl;
		rowLine.clear();

		i++;
	}

	csvFile.close();

	return TRUE;
}

VOID EnumLocalGroupMembers(std::vector <std::wstring> vwsArgs) {
	//__debugbreak();
	
	std::vector <std::map<std::wstring, std::wstring>> vMapResults;
	std::vector <std::wstring> vTargets;

	std::wstring targetHost;
	std::wstring targetsFile;
	std::wstring targetGroup;
	std::wstring csvFilePath;
	
	LPTSTR lpStringSid = NULL;

	NET_API_STATUS nStatus;
	BOOL bStatus = FALSE;
	BOOL bOutCsv = FALSE;
	BOOL bStdOut = FALSE;

	LOCALGROUP_MEMBERS_INFO_2* pBuf;
	DWORD entriesread;
	DWORD totalentries;

	// Process command line arguments
	if (vwsArgs.size() == 0) {
		PrintUsage();
		return;
	}

	size_t i = 0;
	while (i < vwsArgs.size()) {
		if (vwsArgs[i] == L"-h") {
			PrintUsage();
			return;
		}
		else if (vwsArgs[i] == L"-t") {
			targetHost = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-tL") {
			targetsFile = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-g") {
			targetGroup = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"--stdout") {
			bStdOut = TRUE;
			i += 1;
		}
		else if (vwsArgs[i] == L"--csv") {
			csvFilePath = vwsArgs[i + 1];
			bOutCsv = TRUE;
			i += 2;
		}
	}

	// Verify a target group is defined
	if (targetGroup.empty() == TRUE) {
		std::wcout << L"Error: You must specify a target group with '-g'\n" << std::endl;
		PrintUsage();
		return;
	}

	if (targetHost.empty() == FALSE) {
		vTargets.push_back(targetHost);
	}
	else if (targetsFile.empty() == FALSE) {
		std::wfstream fsTargets;
		fsTargets.open(targetsFile, std::ios::in);

		if (fsTargets.is_open()) {
			while (std::getline(fsTargets, targetHost)) {
				vTargets.push_back(targetHost);
			}
		}
		else {
			std::wcout << L"Error: Failed to open targets file\n" << std::endl;
			PrintUsage();
			return;
		}
	}
	else { // Verify at least one target is defined
		std::wcout << L"Error: You must specify target(s) with '-t' or '-tL'\n" << std::endl;
		PrintUsage();
		return;
	}

	size_t j = 0;
	while (j < vTargets.size()) {
		std::wcout << L"[" << j + 1 << L":" << vTargets.size() << L"] " << vTargets[j] << L"...";

		nStatus = NetLocalGroupGetMembers(vTargets[j].c_str(), targetGroup.c_str(),
			2, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesread, &totalentries, NULL);

		// If the call succeeded
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
			std::wcout << totalentries << L" Members" << std::endl;

			i = 0;
			for (i = 0; i < entriesread; i++) {
				bStatus = ConvertSidToStringSid(pBuf->lgrmi2_sid, &lpStringSid);

				if (bStatus == ERROR_NOT_ENOUGH_MEMORY) {
					std::wcout << L"Error: Insufficient memory." << std::endl;
				}
				else if (bStatus == ERROR_INVALID_SID) {
					std::wcout << L"Error: The SID is not valid." << std::endl;
				}
				else if (bStatus == ERROR_INVALID_PARAMETER) {
					std::wcout << L"Error: Invalid parameter passed." << std::endl;
				}
				else {
					std::wstring sidUsage;
					std::map<std::wstring, std::wstring> mapResults;
					
					if (pBuf->lgrmi2_sidusage == SidTypeUser) {
						sidUsage = L"User";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeGroup) {
						sidUsage = L"Group";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeDomain) {
						sidUsage = L"Domain";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeAlias) {
						sidUsage = L"Alias";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeWellKnownGroup) {
						sidUsage = L"Well-Known Group";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeDeletedAccount) {
						sidUsage = L"Deleted Account";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeInvalid) {
						sidUsage = L"Invalid";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeUnknown) {
						sidUsage = L"Unknown";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeComputer) {
						sidUsage = L"Computer";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeLabel) {
						sidUsage = L"Mandatory Integrity Label";
					}
					else if (pBuf->lgrmi2_sidusage == SidTypeLogonSession) {
						sidUsage = L"Logon Session";
					}
					else {
						sidUsage = L"Unknown";
					}

					mapResults[L"Host"] = vTargets[j];
					mapResults[L"Group"] = targetGroup;
					mapResults[L"Member"] = pBuf->lgrmi2_domainandname;
					mapResults[L"SID"] = lpStringSid;
					mapResults[L"SID Usage"] = sidUsage;

					vMapResults.push_back(mapResults);

					// Display results if specified or if not writing to CSV
					if ((bStdOut == TRUE) || (bOutCsv == FALSE)) {
						std::wcout << L"\t" << pBuf->lgrmi2_domainandname << L" (" << sidUsage << L")" << std::endl;
					}

					pBuf++;
				}
			}
		}
		else if (nStatus == ERROR_ACCESS_DENIED) {
			std::wcout << L"Access Denied." << std::endl;
		}
		else if (nStatus == NERR_InvalidComputer) {
			std::wcout << L"Invalid computer name." << std::endl;
		}
		else if (nStatus == ERROR_NO_SUCH_ALIAS) {
			std::wcout << L"Local group does not exist." << std::endl;
		}
		else {
			std::wcout << L"A system error has occured: " << nStatus << std::endl;
		}

		j++;
	}
	
	if (bOutCsv == TRUE) {
		// Save results to a CSV file
		bStatus = ResultsToCSV(vMapResults, csvFilePath);

		if (bStatus == FALSE)
			std::wcout << L"[!] ResultsToCSV() Failed" << std::endl;
	}
}