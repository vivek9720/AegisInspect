#include "core/types.hpp"
namespace AegisInspect::core {
static const std::vector<ExposureHeuristic> exposure_table = {
    ExposureHeuristic{1, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{4, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{5, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{6, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{7, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{8, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{9, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{10, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{11, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{12, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{13, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{14, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{15, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{16, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{17, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{18, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{19, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{20, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{21, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{22, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{23, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{24, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{25, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{26, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{27, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{28, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{29, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{30, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{31, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{32, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{33, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{34, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{35, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{36, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{37, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{38, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{39, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{40, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{41, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{42, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{43, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{44, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{45, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{46, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{47, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{48, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{49, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{50, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{51, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{52, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{53, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{54, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{55, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{56, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{57, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{58, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{59, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{60, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{61, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{62, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{63, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{64, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{65, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{66, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{67, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{68, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{69, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{70, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{71, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{72, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{73, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{74, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{75, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{76, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{77, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{78, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{79, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{80, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{81, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{82, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{83, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{84, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{85, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{86, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{87, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{88, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{89, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{90, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{91, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{92, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{93, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{94, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{95, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{96, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{97, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{98, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{99, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{100, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{101, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{102, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{103, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{104, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{105, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{106, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{107, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{108, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{109, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{110, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{111, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{112, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{113, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{114, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{115, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{116, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{117, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{118, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{119, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{120, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{121, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{122, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{123, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{124, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{125, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{126, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{127, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{128, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{129, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{130, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{131, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{132, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{133, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{134, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{135, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{136, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{137, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{138, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{139, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{140, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{141, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{142, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{143, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{144, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{145, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{146, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{147, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{148, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{149, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{150, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{151, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{152, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{153, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{154, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{155, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{156, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{157, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{158, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{159, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{160, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{161, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{162, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{163, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{164, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{165, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{166, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{167, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{168, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{169, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{170, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{171, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{172, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{173, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{174, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{175, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{176, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{177, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{178, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{179, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{180, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{181, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{182, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{183, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{184, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{185, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{186, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{187, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{188, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{189, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{190, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{191, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{192, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{193, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{194, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{195, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{196, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{197, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{198, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{199, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{200, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{201, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{202, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{203, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{204, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{205, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{206, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{207, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{208, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{209, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{210, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{211, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{212, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{213, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{214, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{215, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{216, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{217, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{218, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{219, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{220, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{221, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{222, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{223, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{224, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{225, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{226, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{227, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{228, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{229, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{230, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{231, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{232, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{233, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{234, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{235, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{236, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{237, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{238, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{239, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{240, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{241, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{242, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{243, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{244, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{245, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{246, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{247, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{248, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{249, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{250, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{251, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{252, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{253, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{254, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{255, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{256, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{257, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{258, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{259, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{260, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{261, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{262, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{263, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{264, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{265, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{266, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{267, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{268, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{269, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{270, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{271, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{272, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{273, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{274, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{275, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{276, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{277, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{278, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{279, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{280, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{281, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{282, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{283, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{284, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{285, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{286, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{287, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{288, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{289, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{290, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{291, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{292, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{293, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{294, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{295, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{296, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{297, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{298, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{299, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{300, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{301, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{302, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{303, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{304, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{305, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{306, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{307, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{308, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{309, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{310, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{311, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{312, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{313, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{314, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{315, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{316, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{317, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{318, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{319, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{320, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{321, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{322, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{323, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{324, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{325, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{326, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{327, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{328, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{329, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{330, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{331, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{332, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{333, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{334, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{335, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{336, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{337, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{338, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{339, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{340, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{341, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{342, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{343, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{344, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{345, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{346, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{347, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{348, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{349, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{350, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{351, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{352, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{353, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{354, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{355, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{356, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{357, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{358, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{359, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{360, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{361, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{362, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{363, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{364, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{365, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{366, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{367, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{368, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{369, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{370, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{371, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{372, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{373, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{374, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{375, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{376, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{377, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{378, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{379, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{380, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{381, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{382, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{383, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{384, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{385, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{386, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{387, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{388, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{389, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{390, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{391, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{392, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{393, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{394, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{395, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{396, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{397, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{398, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{399, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{400, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{401, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{402, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{403, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{404, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{405, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{406, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{407, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{408, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{409, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{410, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{411, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{412, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{413, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{414, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{415, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{416, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{417, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{418, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{419, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{420, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{421, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{422, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{423, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{424, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{425, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{426, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{427, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{428, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{429, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{430, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{431, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{432, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{433, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{434, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{435, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{436, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{437, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{438, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{439, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{440, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{441, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{442, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{443, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{444, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{445, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{446, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{447, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{448, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{449, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{450, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{451, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{452, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{453, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{454, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{455, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{456, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{457, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{458, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{459, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{460, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{461, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{462, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{463, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{464, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{465, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{466, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{467, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{468, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{469, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{470, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{471, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{472, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{473, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{474, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{475, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{476, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{477, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{478, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{479, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{480, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{481, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{482, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{483, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{484, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{485, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{486, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{487, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{488, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{489, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{490, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{491, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{492, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{493, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{494, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{495, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{496, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{497, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{498, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{499, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{500, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{501, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{502, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{503, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{504, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{505, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{506, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{507, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{508, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{509, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{510, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{511, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{512, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{513, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{514, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{515, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{516, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{517, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{518, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{519, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{520, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{521, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{522, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{523, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{524, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{525, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{526, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{527, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{528, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{529, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{530, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{531, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{532, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{533, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{534, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{535, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{536, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{537, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{538, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{539, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{540, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{541, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{542, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{543, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{544, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{545, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{546, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{547, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{548, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{549, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{550, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{551, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{552, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{553, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{554, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{555, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{556, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{557, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{558, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{559, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{560, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{561, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{562, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{563, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{564, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{565, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{566, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{567, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{568, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{569, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{570, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{571, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{572, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{573, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{574, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{575, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{576, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{577, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{578, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{579, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{580, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{581, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{582, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{583, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{584, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{585, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{586, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{587, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{588, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{589, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{590, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{591, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{592, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{593, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{594, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{595, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{596, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{597, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{598, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{599, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{600, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{601, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{602, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{603, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{604, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{605, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{606, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{607, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{608, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{609, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{610, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{611, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{612, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{613, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{614, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{615, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{616, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{617, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{618, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{619, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{620, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{621, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{622, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{623, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{624, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{625, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{626, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{627, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{628, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{629, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{630, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{631, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{632, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{633, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{634, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{635, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{636, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{637, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{638, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{639, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{640, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{641, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{642, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{643, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{644, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{645, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{646, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{647, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{648, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{649, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{650, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{651, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{652, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{653, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{654, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{655, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{656, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{657, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{658, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{659, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{660, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{661, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{662, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{663, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{664, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{665, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{666, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{667, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{668, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{669, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{670, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{671, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{672, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{673, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{674, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{675, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{676, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{677, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{678, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{679, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{680, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{681, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{682, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{683, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{684, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{685, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{686, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{687, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{688, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{689, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{690, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{691, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{692, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{693, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{694, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{695, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{696, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{697, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{698, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{699, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{700, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{701, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{702, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{703, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{704, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{705, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{706, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{707, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{708, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{709, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{710, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{711, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{712, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{713, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{714, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{715, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{716, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{717, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{718, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{719, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{720, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{721, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{722, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{723, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{724, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{725, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{726, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{727, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{728, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{729, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{730, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{731, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{732, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{733, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{734, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{735, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{736, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{737, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{738, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{739, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{740, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{741, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{742, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{743, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{744, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{745, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{746, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{747, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{748, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{749, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{750, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{751, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{752, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{753, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{754, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{755, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{756, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{757, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{758, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{759, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{760, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{761, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{762, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{763, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{764, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{765, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{766, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{767, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{768, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{769, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{770, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{771, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{772, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{773, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{774, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{775, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{776, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{777, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{778, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{779, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{780, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{781, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{782, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{783, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{784, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{785, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{786, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{787, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{788, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{789, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{790, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{791, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{792, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{793, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{794, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{795, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{796, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{797, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{798, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{799, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{800, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{801, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{802, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{803, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{804, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{805, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{806, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{807, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{808, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{809, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{810, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{811, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{812, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{813, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{814, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{815, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{816, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{817, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{818, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{819, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{820, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{821, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{822, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{823, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{824, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{825, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{826, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{827, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{828, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{829, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{830, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{831, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{832, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{833, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{834, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{835, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{836, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{837, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{838, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{839, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{840, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{841, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{842, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{843, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{844, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{845, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{846, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{847, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{848, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{849, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{850, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{851, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{852, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{853, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{854, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{855, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{856, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{857, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{858, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{859, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{860, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{861, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{862, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{863, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{864, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{865, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{866, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{867, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{868, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{869, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{870, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{871, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{872, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{873, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{874, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{875, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{876, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{877, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{878, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{879, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{880, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{881, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{882, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{883, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{884, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{885, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{886, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{887, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{888, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{889, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{890, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{891, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{892, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{893, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{894, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{895, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{896, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{897, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{898, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{899, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{900, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{901, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{902, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{903, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{904, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{905, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{906, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{907, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{908, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{909, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{910, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{911, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{912, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{913, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{914, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{915, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{916, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{917, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{918, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{919, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{920, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{921, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{922, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{923, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{924, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{925, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{926, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{927, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{928, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{929, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{930, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{931, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{932, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{933, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{934, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{935, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{936, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{937, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{938, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{939, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{940, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{941, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{942, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{943, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{944, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{945, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{946, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{947, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{948, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{949, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{950, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{951, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{952, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{953, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{954, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{955, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{956, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{957, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{958, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{959, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{960, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{961, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{962, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{963, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{964, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{965, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{966, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{967, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{968, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{969, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{970, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{971, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{972, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{973, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{974, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{975, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{976, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{977, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{978, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{979, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{980, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{981, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{982, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{983, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{984, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{985, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{986, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{987, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{988, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{989, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{990, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{991, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{992, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{993, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{994, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{995, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{996, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{997, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{998, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{999, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1000, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1001, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1002, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1003, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1004, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1005, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1006, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1007, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1008, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1009, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1010, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1011, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1012, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1013, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1014, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1015, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1016, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1017, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1018, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1019, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1020, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1021, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1022, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1023, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1024, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1025, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1026, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1027, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1028, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1029, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1030, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1031, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1032, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1033, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1034, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1035, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1036, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1037, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1038, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1039, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1040, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1041, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1042, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1043, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1044, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1045, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1046, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1047, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1048, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1049, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1050, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1051, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1052, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1053, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1054, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1055, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1056, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1057, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1058, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1059, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1060, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1061, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1062, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1063, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1064, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1065, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1066, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1067, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1068, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1069, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1070, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1071, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1072, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1073, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1074, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1075, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1076, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1077, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1078, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1079, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1080, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1081, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1082, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1083, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1084, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1085, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1086, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1087, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1088, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1089, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1090, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1091, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1092, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1093, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1094, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1095, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1096, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1097, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1098, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1099, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1100, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1101, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1102, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1103, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1104, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1105, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1106, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1107, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1108, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1109, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1110, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1111, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1112, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1113, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1114, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1115, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1116, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1117, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1118, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1119, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1120, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1121, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1122, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1123, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1124, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1125, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1126, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1127, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1128, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1129, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1130, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1131, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1132, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1133, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1134, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1135, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1136, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1137, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1138, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1139, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1140, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1141, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1142, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1143, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1144, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1145, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1146, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1147, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1148, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1149, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1150, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1151, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1152, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1153, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1154, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1155, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1156, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1157, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1158, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1159, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1160, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1161, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1162, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1163, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1164, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1165, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1166, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1167, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1168, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1169, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1170, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1171, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1172, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1173, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1174, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1175, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1176, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1177, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1178, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1179, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1180, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1181, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1182, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1183, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1184, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1185, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1186, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1187, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1188, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1189, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1190, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1191, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1192, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1193, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1194, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1195, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1196, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1197, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1198, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1199, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1200, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1201, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1202, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1203, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1204, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1205, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1206, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1207, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1208, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1209, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1210, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1211, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1212, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1213, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1214, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1215, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1216, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1217, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1218, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1219, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1220, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1221, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1222, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1223, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1224, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1225, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1226, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1227, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1228, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1229, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1230, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1231, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1232, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1233, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1234, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1235, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1236, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1237, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1238, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1239, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1240, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1241, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1242, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1243, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1244, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1245, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1246, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1247, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1248, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1249, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1250, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1251, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1252, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1253, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1254, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1255, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1256, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1257, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1258, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1259, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1260, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1261, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1262, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1263, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1264, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1265, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1266, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1267, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1268, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1269, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1270, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1271, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1272, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1273, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1274, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1275, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1276, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1277, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1278, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1279, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1280, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1281, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1282, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1283, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1284, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1285, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1286, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1287, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1288, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1289, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1290, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1291, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1292, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1293, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1294, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1295, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1296, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1297, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1298, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1299, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1300, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1301, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1302, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1303, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1304, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1305, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1306, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1307, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1308, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1309, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1310, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1311, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1312, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1313, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1314, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1315, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1316, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1317, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1318, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1319, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1320, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1321, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1322, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1323, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1324, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1325, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1326, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1327, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1328, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1329, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1330, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1331, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1332, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1333, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1334, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1335, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1336, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1337, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1338, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1339, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1340, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1341, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1342, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1343, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1344, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1345, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1346, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1347, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1348, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1349, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1350, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1351, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1352, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1353, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1354, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1355, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1356, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1357, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1358, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1359, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1360, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1361, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1362, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1363, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1364, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1365, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1366, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1367, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1368, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1369, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1370, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1371, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1372, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1373, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1374, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1375, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1376, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1377, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1378, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1379, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1380, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1381, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1382, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1383, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1384, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1385, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1386, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1387, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1388, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1389, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1390, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1391, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1392, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1393, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1394, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1395, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1396, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1397, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1398, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1399, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1400, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1401, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1402, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1403, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1404, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1405, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1406, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1407, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1408, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1409, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1410, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1411, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1412, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1413, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1414, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1415, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1416, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1417, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1418, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1419, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1420, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1421, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1422, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1423, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1424, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1425, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1426, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1427, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1428, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1429, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1430, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1431, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1432, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1433, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1434, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1435, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1436, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1437, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1438, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1439, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1440, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1441, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1442, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1443, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1444, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1445, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1446, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1447, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1448, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1449, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1450, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1451, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1452, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1453, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1454, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1455, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1456, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1457, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1458, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1459, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1460, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1461, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1462, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1463, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1464, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1465, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1466, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1467, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1468, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1469, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1470, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1471, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1472, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1473, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1474, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1475, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1476, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1477, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1478, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1479, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1480, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1481, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1482, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1483, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1484, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1485, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1486, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1487, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1488, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1489, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1490, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1491, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1492, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1493, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1494, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1495, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1496, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1497, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1498, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1499, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1500, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1501, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1502, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1503, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1504, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1505, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1506, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1507, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1508, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1509, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1510, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1511, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1512, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1513, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1514, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1515, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1516, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1517, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1518, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1519, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1520, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1521, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1522, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1523, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1524, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1525, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1526, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1527, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1528, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1529, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1530, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1531, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1532, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1533, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1534, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1535, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1536, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1537, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1538, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1539, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1540, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1541, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1542, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1543, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1544, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1545, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1546, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1547, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1548, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1549, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1550, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1551, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1552, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1553, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1554, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1555, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1556, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1557, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1558, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1559, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1560, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1561, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1562, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1563, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1564, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1565, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1566, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1567, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1568, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1569, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1570, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1571, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1572, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1573, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1574, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1575, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1576, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1577, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1578, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1579, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1580, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1581, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1582, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1583, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1584, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1585, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1586, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1587, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1588, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1589, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1590, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1591, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1592, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1593, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1594, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1595, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1596, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1597, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1598, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1599, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1600, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1601, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1602, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1603, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1604, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1605, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1606, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1607, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1608, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1609, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1610, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1611, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1612, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1613, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1614, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1615, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1616, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1617, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1618, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1619, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1620, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1621, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1622, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1623, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1624, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1625, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1626, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1627, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1628, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1629, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1630, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1631, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1632, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1633, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1634, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1635, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1636, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1637, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1638, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1639, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1640, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1641, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1642, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1643, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1644, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1645, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1646, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1647, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1648, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1649, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1650, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1651, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1652, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1653, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1654, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1655, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1656, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1657, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1658, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1659, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1660, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1661, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1662, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1663, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1664, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1665, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1666, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1667, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1668, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1669, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1670, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1671, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1672, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1673, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1674, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1675, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1676, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1677, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1678, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1679, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1680, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1681, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1682, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1683, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1684, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1685, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1686, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1687, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1688, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1689, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1690, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1691, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1692, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1693, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1694, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1695, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1696, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1697, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1698, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1699, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1700, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1701, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1702, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1703, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1704, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1705, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1706, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1707, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1708, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1709, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1710, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1711, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1712, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1713, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1714, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1715, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1716, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1717, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1718, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1719, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1720, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1721, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1722, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1723, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1724, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1725, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1726, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1727, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1728, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1729, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1730, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1731, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1732, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1733, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1734, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1735, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1736, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1737, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1738, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1739, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1740, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1741, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1742, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1743, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1744, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1745, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1746, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1747, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1748, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1749, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1750, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1751, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1752, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1753, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1754, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1755, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1756, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1757, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1758, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1759, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1760, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1761, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1762, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1763, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1764, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1765, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1766, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1767, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1768, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1769, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1770, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1771, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1772, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1773, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1774, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1775, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1776, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1777, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1778, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1779, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1780, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1781, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1782, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1783, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1784, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1785, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1786, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1787, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1788, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1789, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1790, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1791, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1792, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1793, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1794, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1795, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1796, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1797, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1798, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1799, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1800, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1801, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1802, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1803, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1804, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1805, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1806, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1807, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1808, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1809, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1810, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1811, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1812, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1813, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1814, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1815, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1816, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1817, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1818, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1819, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1820, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1821, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1822, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1823, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1824, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1825, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1826, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1827, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1828, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1829, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1830, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1831, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1832, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1833, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1834, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1835, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1836, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1837, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1838, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1839, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1840, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1841, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1842, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1843, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1844, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1845, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1846, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1847, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1848, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1849, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1850, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1851, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1852, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1853, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1854, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1855, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1856, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1857, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1858, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1859, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1860, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1861, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1862, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1863, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1864, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1865, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1866, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1867, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1868, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1869, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1870, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1871, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1872, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1873, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1874, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1875, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1876, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1877, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1878, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1879, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1880, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1881, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1882, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1883, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1884, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1885, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1886, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1887, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1888, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1889, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1890, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1891, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1892, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1893, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1894, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1895, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1896, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1897, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1898, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1899, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1900, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1901, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1902, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1903, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1904, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1905, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1906, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1907, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1908, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1909, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1910, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1911, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1912, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1913, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1914, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1915, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1916, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1917, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1918, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1919, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1920, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1921, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1922, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1923, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1924, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1925, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1926, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1927, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1928, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1929, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1930, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1931, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1932, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1933, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1934, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1935, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1936, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1937, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1938, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1939, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1940, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1941, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1942, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1943, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1944, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1945, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1946, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1947, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1948, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1949, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1950, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1951, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1952, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1953, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1954, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1955, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1956, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1957, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1958, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1959, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1960, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1961, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1962, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1963, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1964, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1965, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1966, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1967, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1968, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1969, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1970, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1971, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1972, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1973, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1974, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1975, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1976, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1977, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1978, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1979, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1980, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{1981, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1982, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1983, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1984, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1985, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1986, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1987, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1988, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{1989, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1990, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1991, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{1992, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{1993, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{1994, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{1995, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{1996, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{1997, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{1998, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{1999, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2000, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2001, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2002, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2003, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2004, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2005, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2006, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2007, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2008, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2009, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2010, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2011, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2012, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2013, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2014, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2015, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2016, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2017, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2018, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2019, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2020, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2021, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2022, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2023, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2024, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2025, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2026, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2027, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2028, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2029, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2030, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2031, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2032, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2033, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2034, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2035, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2036, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2037, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2038, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2039, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2040, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2041, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2042, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2043, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2044, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2045, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2046, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2047, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2048, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2049, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2050, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2051, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2052, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2053, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2054, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2055, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2056, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2057, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2058, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2059, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2060, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2061, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2062, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2063, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2064, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2065, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2066, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2067, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2068, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2069, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2070, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2071, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2072, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2073, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2074, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2075, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2076, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2077, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2078, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2079, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2080, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2081, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2082, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2083, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2084, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2085, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2086, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2087, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2088, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2089, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2090, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2091, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2092, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2093, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2094, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2095, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2096, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2097, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2098, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2099, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2100, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2101, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2102, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2103, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2104, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2105, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2106, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2107, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2108, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2109, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2110, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2111, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2112, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2113, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2114, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2115, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2116, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2117, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2118, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2119, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2120, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2121, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2122, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2123, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2124, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2125, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2126, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2127, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2128, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2129, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2130, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2131, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2132, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2133, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2134, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2135, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2136, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2137, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2138, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2139, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2140, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2141, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2142, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2143, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2144, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2145, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2146, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2147, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2148, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2149, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2150, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2151, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2152, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2153, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2154, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2155, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2156, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2157, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2158, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2159, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2160, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2161, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2162, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2163, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2164, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2165, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2166, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2167, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2168, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2169, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2170, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2171, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2172, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2173, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2174, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2175, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2176, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2177, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2178, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2179, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2180, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2181, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2182, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2183, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2184, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2185, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2186, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2187, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2188, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2189, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2190, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2191, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2192, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2193, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2194, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2195, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2196, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2197, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2198, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2199, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2200, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2201, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2202, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2203, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2204, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2205, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2206, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2207, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2208, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2209, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2210, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2211, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2212, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2213, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2214, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2215, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2216, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2217, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2218, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2219, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2220, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2221, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2222, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2223, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2224, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2225, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2226, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2227, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2228, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2229, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2230, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2231, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2232, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2233, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2234, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2235, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2236, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2237, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2238, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2239, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2240, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2241, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2242, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2243, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2244, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2245, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2246, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2247, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2248, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2249, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2250, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2251, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2252, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2253, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2254, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2255, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2256, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2257, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2258, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2259, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2260, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2261, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2262, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2263, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2264, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2265, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2266, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2267, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2268, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2269, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2270, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2271, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2272, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2273, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2274, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2275, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2276, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2277, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2278, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2279, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2280, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2281, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2282, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2283, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2284, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2285, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2286, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2287, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2288, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2289, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2290, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2291, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2292, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2293, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2294, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2295, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2296, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2297, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2298, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2299, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2300, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2301, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2302, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2303, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2304, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2305, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2306, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2307, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2308, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2309, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2310, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2311, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2312, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2313, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2314, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2315, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2316, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2317, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2318, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2319, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2320, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2321, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2322, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2323, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2324, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2325, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2326, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2327, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2328, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2329, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2330, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2331, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2332, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2333, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2334, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2335, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2336, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2337, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2338, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2339, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2340, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2341, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2342, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2343, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2344, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2345, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2346, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2347, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2348, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2349, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2350, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2351, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2352, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2353, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2354, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2355, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2356, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2357, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2358, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2359, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2360, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2361, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2362, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2363, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2364, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2365, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2366, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2367, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2368, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2369, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2370, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2371, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2372, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2373, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2374, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2375, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2376, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2377, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2378, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2379, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2380, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2381, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2382, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2383, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2384, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2385, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2386, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2387, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2388, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2389, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2390, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2391, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2392, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2393, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2394, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2395, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2396, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2397, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2398, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2399, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2400, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2401, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2402, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2403, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2404, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2405, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2406, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2407, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2408, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2409, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2410, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2411, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2412, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2413, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2414, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2415, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2416, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2417, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2418, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2419, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2420, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2421, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2422, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2423, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2424, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2425, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2426, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2427, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2428, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2429, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2430, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2431, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2432, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2433, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2434, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2435, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2436, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2437, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2438, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2439, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2440, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2441, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2442, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2443, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2444, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2445, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2446, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2447, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2448, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2449, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2450, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2451, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2452, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2453, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2454, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2455, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2456, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2457, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2458, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2459, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2460, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2461, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2462, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2463, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2464, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2465, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2466, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2467, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2468, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2469, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2470, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2471, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2472, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2473, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2474, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2475, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2476, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2477, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2478, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2479, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2480, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2481, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2482, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2483, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2484, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2485, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2486, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2487, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2488, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2489, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2490, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2491, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2492, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2493, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2494, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2495, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2496, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2497, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2498, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2499, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2500, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2501, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2502, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2503, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2504, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2505, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2506, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2507, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2508, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2509, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2510, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2511, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2512, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2513, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2514, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2515, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2516, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2517, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2518, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2519, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2520, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2521, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2522, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2523, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2524, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2525, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2526, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2527, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2528, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2529, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2530, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2531, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2532, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2533, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2534, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2535, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2536, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2537, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2538, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2539, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2540, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2541, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2542, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2543, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2544, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2545, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2546, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2547, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2548, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2549, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2550, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2551, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2552, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2553, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2554, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2555, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2556, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2557, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2558, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2559, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2560, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2561, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2562, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2563, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2564, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2565, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2566, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2567, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2568, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2569, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2570, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2571, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2572, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2573, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2574, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2575, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2576, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2577, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2578, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2579, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2580, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2581, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2582, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2583, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2584, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2585, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2586, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2587, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2588, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2589, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2590, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2591, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2592, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2593, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2594, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2595, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2596, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2597, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2598, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2599, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2600, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2601, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2602, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2603, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2604, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2605, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2606, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2607, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2608, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2609, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2610, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2611, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2612, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2613, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2614, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2615, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2616, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2617, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2618, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2619, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2620, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2621, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2622, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2623, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2624, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2625, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2626, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2627, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2628, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2629, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2630, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2631, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2632, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2633, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2634, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2635, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2636, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2637, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2638, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2639, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2640, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2641, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2642, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2643, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2644, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2645, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2646, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2647, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2648, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2649, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2650, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2651, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2652, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2653, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2654, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2655, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2656, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2657, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2658, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2659, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2660, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2661, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2662, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2663, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2664, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2665, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2666, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2667, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2668, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2669, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2670, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2671, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2672, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2673, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2674, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2675, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2676, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2677, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2678, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2679, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2680, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2681, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2682, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2683, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2684, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2685, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2686, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2687, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2688, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2689, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2690, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2691, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2692, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2693, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2694, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2695, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2696, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2697, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2698, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2699, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2700, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2701, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2702, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2703, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2704, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2705, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2706, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2707, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2708, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2709, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2710, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2711, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2712, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2713, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2714, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2715, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2716, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2717, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2718, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2719, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2720, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2721, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2722, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2723, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2724, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2725, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2726, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2727, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2728, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2729, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2730, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2731, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2732, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2733, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2734, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2735, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2736, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2737, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2738, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2739, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2740, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2741, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2742, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2743, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2744, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2745, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2746, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2747, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2748, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2749, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2750, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2751, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2752, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2753, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2754, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2755, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2756, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2757, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2758, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2759, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2760, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2761, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2762, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2763, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2764, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2765, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2766, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2767, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2768, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2769, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2770, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2771, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2772, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2773, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2774, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2775, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2776, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2777, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2778, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2779, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2780, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2781, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2782, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2783, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2784, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2785, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2786, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2787, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2788, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2789, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2790, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2791, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2792, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2793, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2794, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2795, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2796, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2797, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2798, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2799, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2800, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2801, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2802, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2803, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2804, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2805, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2806, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2807, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2808, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2809, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2810, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2811, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2812, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2813, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2814, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2815, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2816, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2817, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2818, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2819, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2820, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2821, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2822, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2823, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2824, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2825, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2826, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2827, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2828, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2829, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2830, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2831, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2832, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2833, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2834, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2835, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2836, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2837, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2838, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2839, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2840, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2841, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2842, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2843, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2844, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2845, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2846, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2847, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2848, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2849, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2850, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2851, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2852, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2853, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2854, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2855, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2856, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2857, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2858, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2859, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2860, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2861, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2862, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2863, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2864, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2865, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2866, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2867, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2868, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2869, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2870, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2871, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2872, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2873, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2874, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2875, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2876, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2877, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2878, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2879, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2880, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2881, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2882, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2883, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2884, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2885, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2886, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2887, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2888, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2889, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2890, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2891, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2892, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2893, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2894, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2895, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2896, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2897, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2898, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2899, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2900, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2901, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2902, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2903, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2904, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2905, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2906, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2907, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2908, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2909, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2910, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2911, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2912, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2913, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2914, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2915, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2916, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2917, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2918, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2919, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2920, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2921, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2922, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2923, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2924, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2925, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2926, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2927, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2928, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2929, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2930, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2931, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2932, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2933, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2934, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2935, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2936, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2937, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2938, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2939, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2940, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2941, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2942, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2943, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2944, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2945, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2946, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2947, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2948, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2949, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2950, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2951, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2952, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2953, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2954, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2955, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2956, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2957, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2958, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2959, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2960, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2961, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2962, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2963, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2964, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2965, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2966, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2967, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2968, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2969, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2970, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2971, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2972, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2973, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2974, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2975, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2976, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2977, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2978, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2979, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2980, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{2981, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2982, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2983, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2984, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2985, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2986, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2987, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2988, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{2989, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2990, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2991, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{2992, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{2993, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{2994, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{2995, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{2996, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{2997, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{2998, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{2999, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3000, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3001, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3002, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3003, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3004, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3005, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3006, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3007, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3008, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3009, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3010, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3011, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3012, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3013, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3014, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3015, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3016, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3017, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3018, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3019, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3020, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3021, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3022, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3023, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3024, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3025, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3026, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3027, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3028, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3029, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3030, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3031, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3032, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3033, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3034, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3035, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3036, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3037, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3038, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3039, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3040, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3041, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3042, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3043, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3044, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3045, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3046, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3047, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3048, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3049, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3050, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3051, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3052, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3053, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3054, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3055, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3056, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3057, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3058, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3059, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3060, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3061, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3062, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3063, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3064, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3065, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3066, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3067, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3068, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3069, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3070, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3071, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3072, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3073, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3074, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3075, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3076, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3077, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3078, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3079, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3080, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3081, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3082, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3083, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3084, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3085, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3086, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3087, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3088, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3089, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3090, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3091, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3092, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3093, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3094, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3095, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3096, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3097, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3098, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3099, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3100, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3101, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3102, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3103, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3104, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3105, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3106, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3107, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3108, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3109, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3110, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3111, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3112, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3113, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3114, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3115, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3116, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3117, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3118, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3119, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3120, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3121, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3122, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3123, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3124, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3125, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3126, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3127, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3128, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3129, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3130, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3131, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3132, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3133, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3134, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3135, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3136, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3137, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3138, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3139, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3140, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3141, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3142, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3143, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3144, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3145, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3146, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3147, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3148, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3149, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3150, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3151, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3152, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3153, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3154, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3155, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3156, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3157, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3158, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3159, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3160, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3161, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3162, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3163, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3164, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3165, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3166, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3167, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3168, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3169, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3170, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3171, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3172, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3173, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3174, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3175, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3176, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3177, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3178, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3179, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3180, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3181, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3182, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3183, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3184, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3185, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3186, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3187, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3188, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3189, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3190, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3191, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3192, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3193, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3194, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3195, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3196, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3197, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3198, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3199, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3200, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3201, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3202, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3203, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3204, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3205, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3206, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3207, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3208, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3209, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3210, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3211, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3212, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3213, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3214, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3215, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3216, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3217, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3218, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3219, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3220, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3221, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3222, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3223, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3224, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3225, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3226, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3227, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3228, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3229, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3230, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3231, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3232, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3233, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3234, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3235, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3236, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3237, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3238, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3239, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3240, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3241, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3242, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3243, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3244, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3245, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3246, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3247, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3248, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3249, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3250, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3251, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3252, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3253, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3254, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3255, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3256, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3257, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3258, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3259, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3260, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3261, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3262, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3263, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3264, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3265, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3266, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3267, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3268, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3269, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3270, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3271, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3272, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3273, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3274, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3275, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3276, "udp", "admin", "inventory drift", "document business owner"},
    ExposureHeuristic{3277, "tcp", "database", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3278, "tcp", "web", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3279, "tcp", "mail", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3280, "udp", "directory", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3281, "tcp", "storage", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3282, "tcp", "voice", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3283, "tcp", "iot", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3284, "udp", "monitoring", "inventory drift", "document business owner"},
    ExposureHeuristic{3285, "tcp", "logging", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3286, "tcp", "proxy", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3287, "tcp", "vpn", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3288, "udp", "admin", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3289, "tcp", "database", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3290, "tcp", "web", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3291, "tcp", "mail", "credential attack surface", "place behind access gateway"},
    ExposureHeuristic{3292, "udp", "directory", "inventory drift", "document business owner"},
    ExposureHeuristic{3293, "tcp", "storage", "legacy service", "alert on unexpected clients"},
    ExposureHeuristic{3294, "tcp", "voice", "remote administration", "review firewall ordering"},
    ExposureHeuristic{3295, "tcp", "iot", "data exfiltration path", "validate detection coverage"},
    ExposureHeuristic{3296, "udp", "monitoring", "internet exposure", "restrict source networks"},
    ExposureHeuristic{3297, "tcp", "logging", "cleartext protocol", "require encrypted transport"},
    ExposureHeuristic{3298, "tcp", "proxy", "lateral movement", "monitor authentication failures"},
    ExposureHeuristic{3299, "tcp", "vpn", "credential attack surface", "place behind access gateway"},
};
const std::vector<ExposureHeuristic>& exposure_heuristics(){ return exposure_table; }
std::vector<ExposureHeuristic> exposure_heuristics_for_zone(std::string_view zone){ std::vector<ExposureHeuristic> out; auto wanted=lower(zone); for(const auto& h: exposure_table){ if(wanted==lower(h.asset_zone)) out.push_back(h); } return out; }
}
