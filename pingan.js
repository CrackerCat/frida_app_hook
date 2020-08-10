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
                    var s3 = Java.cast(args[3], str);
                    console.log("param3>>>>>>>" +  s3);
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
Java.perform(function () {
    
    var isHook = true;
    var util=Java.use("com.pingan.hrx.commons.util.LogUtils");
    util.punch.overload("java.lang.String").implementation=function(arg1){
        send("punch Hook Start...");
        send(arg1)
        if(isHook){
            c();
            isHook = false;
        }
        var result = this.punch(arg1)
        return result
    }
    var AESUtils=Java.use("com.pingan.hrx.commons.util.AESUtils");
    AESUtils.getFromServer1.overload().implementation=function(){
        send("getFromServer1 Hook Start...");
        var result = this.getFromServer1()
        send(result)
        return result
    }
    AESUtils.getFromServer2.overload().implementation=function(){
        send("getFromServer2 Hook Start...");
        var result = this.getFromServer2()
        send(result)
        return result
    }
    var TecentLocationUtils=Java.use("com.pingan.hrx.commons.util.TecentLocationUtils");
    TecentLocationUtils.onSuccess.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'double', 'double', 'java.lang.String', 'java.lang.String').implementation=function(arg1,arg2,arg3,arg4,arg5,arg6,arg7){
        send("punch Hook Start...");
        send("[city:"+arg1+" street:"+arg2+" address:"+arg3+" lat:"+arg4+" lng:"+arg5+" nation:"+arg6+"]")
        var result = this.onSuccess(arg1,arg2,arg3,arg4,arg5,arg6,arg7)
        return result
    }
    var TencentLocation=Java.use("c.t.m.g.en");
    TencentLocation.getCity.overload().implementation=function(){
        var result = this.getCity()
        console.log("getCity Hook Start..." + result);
        return result
    }
    TencentLocation.getProvince.overload().implementation=function(){
        var result = this.getProvince()
        console.log("getProvince Hook Start..." + result);
        return result
    }
    TencentLocation.getStreet.overload().implementation=function(){
        var result = this.getStreet()
        console.log("getStreet Hook Start..." + result);
        return result
    }
    TencentLocation.getAddress.overload().implementation=function(){
        var result = this.getAddress()
        console.log("getAddress Hook Start..." + result);
        return result
    }
    TencentLocation.getNation.overload().implementation=function(){
        var result = this.getNation()
        console.log("getNation Hook Start..." + result);
        return result
    }
    TencentLocation.getLatitude.overload().implementation=function(){
        var result = this.getLatitude()
        console.log("getLatitude Hook Start..." + result);
        return result
    }
    TencentLocation.getLongitude.overload().implementation=function(){
        var result = this.getLongitude()
        console.log("getLongitude Hook Start..." + result);
        return result
    }
    TencentLocation.getGPSRssi.overload().implementation=function(){
        var result = this.getGPSRssi()
        console.log("getGPSRssi Hook Start..." + result);
        return result
    }
    TencentLocation.getAltitude.overload().implementation=function(){
        var result = this.getAltitude()
        console.log("getAltitude Hook Start..."+result)
        return result
    }
    TencentLocation.getProvider.overload().implementation=function(){
        var result = this.getProvider()
        console.log("getProvider Hook Start..."+result)
        return result
    }
    // TecentLocationUtils.onLocationChanged.overload('com.tencent.map.geolocation.TencentLocation', 'int', 'java.lang.String').implementation=function(arg1,arg2,arg3){
    //     send("onLocationChanged Hook Start...");
    //     send(arg1.getClass().getName())
    //     var result = this.onLocationChanged(arg1,arg2,arg3)
    //     send(result)
    //     return result
    // }
});
