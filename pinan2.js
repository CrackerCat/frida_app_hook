function c(){
        const hooks = Module.load('libSparta.so');
        var Exports = hooks.enumerateExports();
        for(var i = 0; i < Exports.length; i++) {
            
            var str;
            Java.perform(function () {
                str = Java.use("java.lang.String");
            });
            if(Exports[i].name=="start"){
                //函数类型
                console.log("type:",Exports[i].type);
                //函数名称
                console.log("name:",Exports[i].name);
                //函数地址
                console.log("address:",(Exports[i].address));
                Interceptor.attach(Exports[i].address, {
                    onEnter: function (args) {
                        // Java.vm.getEnv().GetObjectClass(args[0])
                        // console.log("param1>>>>>>>>>>>>>>>>--------------------------"+Memory.readUtf16String(args[0]));
                    },
                    onLeave: function (retval) {
                        // console.log("param1>>>>>>>>>>>>>>>>--------------------------")
                        // var result=Java.vm.getEnv().newStringUtf(retval)
                        // console.log("param result>>>>>>>>>>>>>>>>--------------------------"+Java.cast(retval, str));
                    }
                });
            }
        }
}
c()