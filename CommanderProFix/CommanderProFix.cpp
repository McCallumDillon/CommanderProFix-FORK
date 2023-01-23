//
//  CommanderProFix.cpp
//  CommanderProFix
//
//  Copyright © 2023 dreamwhite. All rights reserved.
//

#include <IOKit/IOService.h>
#include <Headers/kern_api.hpp>
#include <Headers/kern_devinfo.hpp>
#include <Headers/plugin_start.hpp>
#include <Headers/kern_policy.hpp>

static const char *bootargOff[] {
	"-cpfoff"
};

static const char *bootargDebug[] {
	"-cpfdbg"
};

static const char *bootargBeta[] {
	"-cpfbeta"
};


static bool verboseProcessLogging;

const char *procBlacklist[10] = {};

struct CommanderProFixPolicy {

	/**
	 *  Policy to restrict blacklisted process execution
	 */
	static int policyCheckExecve(kauth_cred_t cred, struct vnode *vp, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptlabel, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen) {
		char pathbuf[MAXPATHLEN];
		int len = MAXPATHLEN;
		int err = vn_getpath(vp, pathbuf, &len);

		if (err == 0) {
			// Uncomment for more verbose output.
			DBGLOG_COND(verboseProcessLogging, "cpf", "got request %s", pathbuf);

			for (auto &proc : procBlacklist) {
				if (proc == nullptr) break;
				if (strcmp(pathbuf, proc) == 0) {
					DBGLOG("cpf", "restricting process %s", pathbuf);
					return EPERM;
				}
			}
		}

		return 0;
	}

	static void getBlockedProcesses(BaseDeviceInfo *info) {
		// Updates procBlacklist with list of processes to block
		char duip[128] { "auto" };

		char *value = reinterpret_cast<char *>(&duip[0]);
		value[sizeof(duip) - 1] = '\0';
		size_t i = 0;

		procBlacklist[i++] = (char *)"/usr/libexec/ioupsd";


		for (auto &proc : procBlacklist) {
			if (proc == nullptr) break;
			DBGLOG("cpf", "blocking %s", proc);
		}
	}

	/**
	 *  Default dummy BSD init policy
	 */
	static void policyInitBSD(mac_policy_conf *conf) {
		DBGLOG("cpf", "init bsd policy on %u", getKernelVersion());
	}

	/**
	 *  TrustedBSD policy options
	 */
	mac_policy_ops policyOps {
		.mpo_policy_initbsd = policyInitBSD,
		.mpo_vnode_check_exec = policyCheckExecve
	};

	/**
	 *  Full policy name
	 */
#ifdef DEBUG
	static constexpr const char *fullName {xStringify(PRODUCT_NAME) " Kernel Extension " xStringify(MODULE_VERSION) " DEBUG build"};
#else
	static constexpr const char *fullName {xStringify(PRODUCT_NAME) " Kernel Extension " xStringify(MODULE_VERSION)};
#endif

	/**
	 *  Policy controller
	 */
	Policy policy;

	/**
	 Policy constructor.
	 */
	CommanderProFixPolicy() : policy(xStringify(PRODUCT_NAME), fullName, &policyOps) {}
};

static CommanderProFixPolicy commanderProFixPolicy;

void rerouteHvVmm(KernelPatcher &patcher);

PluginConfiguration ADDPR(config) {
	xStringify(PRODUCT_NAME),
	parseModuleVersion(xStringify(MODULE_VERSION)),
	LiluAPI::AllowNormal | LiluAPI::AllowInstallerRecovery | LiluAPI::AllowSafeMode,
	bootargOff,
	arrsize(bootargOff),
	bootargDebug,
	arrsize(bootargDebug),
	bootargBeta,
	arrsize(bootargBeta),
	KernelVersion::MountainLion,
	KernelVersion::Ventura,
	[]() {
		DBGLOG("cpf", "restriction policy plugin loaded");
		verboseProcessLogging = checkKernelArgument("-cpfproc");
		auto di = BaseDeviceInfo::get();
		CommanderProFixPolicy::getBlockedProcesses(&di);
		commanderProFixPolicy.policy.registerPolicy();
	}
};
