export namespace fixer {
	
	export class CommandLog {
	    dir: string;
	    command: string;
	    output: string;
	    success: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CommandLog(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dir = source["dir"];
	        this.command = source["command"];
	        this.output = source["output"];
	        this.success = source["success"];
	    }
	}
	export class Request {
	    ecosystem: string;
	    name: string;
	    currentVersion: string;
	    targetVersion: string;
	    manifest: string;
	    direct: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Request(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ecosystem = source["ecosystem"];
	        this.name = source["name"];
	        this.currentVersion = source["currentVersion"];
	        this.targetVersion = source["targetVersion"];
	        this.manifest = source["manifest"];
	        this.direct = source["direct"];
	    }
	}
	export class Result {
	    request: Request;
	    success: boolean;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.request = this.convertValues(source["request"], Request);
	        this.success = source["success"];
	        this.message = source["message"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Report {
	    results: Result[];
	    commands: CommandLog[];
	    changedFiles: string[];
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.results = this.convertValues(source["results"], Result);
	        this.commands = this.convertValues(source["commands"], CommandLog);
	        this.changedFiles = source["changedFiles"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

export namespace main {
	
	export class ScanReport {
	    root: string;
	    components: sbom.Component[];
	    findings: vuln.Finding[];
	    manifests: string[];
	    warnings: string[];
	    ecosystems: Record<string, number>;
	    severities: Record<string, number>;
	    gitRepo: boolean;
	    gitDirty: string[];
	    scannedAt: string;
	    durationMs: number;
	
	    static createFrom(source: any = {}) {
	        return new ScanReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.root = source["root"];
	        this.components = this.convertValues(source["components"], sbom.Component);
	        this.findings = this.convertValues(source["findings"], vuln.Finding);
	        this.manifests = source["manifests"];
	        this.warnings = source["warnings"];
	        this.ecosystems = source["ecosystems"];
	        this.severities = source["severities"];
	        this.gitRepo = source["gitRepo"];
	        this.gitDirty = source["gitDirty"];
	        this.scannedAt = source["scannedAt"];
	        this.durationMs = source["durationMs"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FixReport {
	    fix?: fixer.Report;
	    rescan?: ScanReport;
	
	    static createFrom(source: any = {}) {
	        return new FixReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fix = this.convertValues(source["fix"], fixer.Report);
	        this.rescan = this.convertValues(source["rescan"], ScanReport);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace sbom {
	
	export class Component {
	    name: string;
	    version: string;
	    ecosystem: string;
	    purl: string;
	    manifest: string;
	    direct: boolean;
	    dev: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Component(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.version = source["version"];
	        this.ecosystem = source["ecosystem"];
	        this.purl = source["purl"];
	        this.manifest = source["manifest"];
	        this.direct = source["direct"];
	        this.dev = source["dev"];
	    }
	}

}

export namespace vuln {
	
	export class Vulnerability {
	    id: string;
	    aliases: string[];
	    summary: string;
	    severity: string;
	    fixedVersion: string;
	    url: string;
	
	    static createFrom(source: any = {}) {
	        return new Vulnerability(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.aliases = source["aliases"];
	        this.summary = source["summary"];
	        this.severity = source["severity"];
	        this.fixedVersion = source["fixedVersion"];
	        this.url = source["url"];
	    }
	}
	export class Finding {
	    component: sbom.Component;
	    vulns: Vulnerability[];
	    severity: string;
	    fixVersion: string;
	    fixable: boolean;
	    fullyFixed: boolean;
	    majorBump: boolean;
	    targetVulnerable: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.component = this.convertValues(source["component"], sbom.Component);
	        this.vulns = this.convertValues(source["vulns"], Vulnerability);
	        this.severity = source["severity"];
	        this.fixVersion = source["fixVersion"];
	        this.fixable = source["fixable"];
	        this.fullyFixed = source["fullyFixed"];
	        this.majorBump = source["majorBump"];
	        this.targetVulnerable = source["targetVulnerable"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

