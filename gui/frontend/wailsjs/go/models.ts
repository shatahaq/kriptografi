export namespace main {
	
	export class BuildInfo {
	    id: string;
	    encFile: string;
	    decFile: string;
	    keyFile: string;
	    encSize: string;
	    decSize: string;
	    timestamp: string;
	
	    static createFrom(source: any = {}) {
	        return new BuildInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.encFile = source["encFile"];
	        this.decFile = source["decFile"];
	        this.keyFile = source["keyFile"];
	        this.encSize = source["encSize"];
	        this.decSize = source["decSize"];
	        this.timestamp = source["timestamp"];
	    }
	}
	export class BuildResult {
	    id: string;
	    encFile: string;
	    decFile: string;
	    keyFile: string;
	    timestamp: string;
	    success: boolean;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new BuildResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.encFile = source["encFile"];
	        this.decFile = source["decFile"];
	        this.keyFile = source["keyFile"];
	        this.timestamp = source["timestamp"];
	        this.success = source["success"];
	        this.error = source["error"];
	    }
	}

}

