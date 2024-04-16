const lwsint = tjs[Symbol.for('tjs.internal')].core.lws_load_native();


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
	{
		name: 'defprot'
	},
    {
        name: 'http',
        callback: ()=>{
            console.log('http-server callback');
        }
    }
], [
	{
		mountpoint: '/',
		origin: './mount-origin',
		def: 'index.html',
		origin_protocol: lwsint.protocol_types.FILE
	},{
		mountpoint: '/dyn',
		protocol: 'http',
		origin_protocol: lwsint.protocol_types.CALLBACK
	}
]);

await new Promise(re=>setTimeout(()=>{
    re();
}, 10e3));
