const lwsint = tjs[Symbol.for('tjs.internal')].core.lws_load_native();
const reasons = lwsint.reasons;
const write_protocols = lwsint.write_protocols;

/*
class LWSContext{
	constructor(options, plugins){
		this.#ctx = new lwsint.LWSContext({port: 1234}, [
			{ name: 'http-server', callback: ()=>{
				console.log('http-server callback');
			} }
		]);
	}

}
*/

const ctx = new lwsint.LWSContext();

ctx.add_vhost({ port: 1234, vhost_name: 'http' }, [
	/*{
		name: 'defprot'
	},*/
    {
        name: 'http',
        callback: (reason, buf, wsi)=>{
			const reasonStr = Object.entries(reasons).find(([n,k])=>k === reason) ?? k;
            console.log('http-server callback', reasonStr, buf, wsi);
			switch(reason){
				default:
					return 0;
				case reasons.HTTP:
					console.log('asdasd1');
					const info = wsi.info();
					wsi.write_header(200, []) //[["content-type", "123"]]);
					console.log('asdasd2');
					try{
						wsi.wait_writable();
					}catch(e){}
					return 0;
				case reasons.HTTP_WRITEABLE:
					try{
					console.log('asdasd3', write_protocols);
					wsi.write("Hello, world!", write_protocols.HTTP_FINAL);
					wsi.complete();
					}catch(e){
						console.error(e);
					}
					return 0;
			}
        }
    }
], [
	/*{
		mountpoint: '/',
		origin: './mount-origin',
		def: 'index.html',
		protocol: 'defprot',
		origin_protocol: lwsint.protocol_types.FILE
	},*/{
		mountpoint: '/dyn',
		protocol: 'http',
		origin_protocol: lwsint.protocol_types.CALLBACK
	}
]);

await new Promise(re=>setTimeout(()=>{
    re();
}, 4e3));
