const lwsint = tjs[Symbol.for('tjs.internal')].core.lws_load_native();

console.log(lwsint);

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

console.log(ctx, Object.getPrototypeOf(ctx));
ctx.add_vhost({ port: 1234, vhost_name: 'default' }, [
    {
        name: 'http-server',
        callback: ()=>{
            console.log('http-server callback');
        }
    }
], [
	{
		mountpoint: '/',
		origin: 'http-server',
		origin_protocol: 6
	}
]);

await new Promise(re=>setTimeout(()=>{
    re();
}, 10e3));
