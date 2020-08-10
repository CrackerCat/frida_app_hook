Java.perform(function () {

    var APIUtils=Java.use("com.drcuiyutao.lib.api.APIUtils");
    
    APIUtils.updateBodyString.overload('java.lang.String').implementation=function(arg1){
        send("list Hook Start...");
        send(arg1)
        var result= this.updateBodyString(arg1)
        send(result)
        return result
    }
});