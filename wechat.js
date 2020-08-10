// js hook wechat  7.0.17
// account.bind.ui.MobileFriendUI b -》 app.ak.c -> br.d.b ->br.d$9.onDone -> MMFragmentActivity.startActivity
Java.perform(function () {

    var MobileFriendUI=Java.use("com.tencent.mm.plugin.account.bind.ui.MobileFriendUI");
    
    MobileFriendUI.b.overload('com.tencent.mm.plugin.account.friend.a.a').implementation=function(arg1){
        send("MobileFriendUI Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        send(arg1.getUsername())
        return this.b(arg1)
    }

    var a=Java.use("com.tencent.mm.plugin.account.friend.a.a");
    
    // a.convertFrom.overload('android.database.Cursor').implementation=function(arg1){
    //     send("convertFrom Hook Start...");
    //     console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    //     return this.convertFrom(arg1)
    // }
    
    // a.ap.overload('[B').implementation=function(arg1){
    //     send("convertFrom Hook Start...");
    //     console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    //     var result =  this.ap(arg1)
    //     send(this.iJS.value)
    //     send(this.iJT.value)
    //     return result
    // }

    var a=Java.use("com.tencent.mm.plugin.finder.api.b$a");
    a.crX.overload().implementation=function(){
        send("crX Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        var result =  this.crX()
        return result
    }

    var db=Java.use("com.tencent.mm.aj.d$b");
    db.aBj.overload().implementation=function(){
        send("aBj Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        var result =  this.aBj()
        return result
    }
    var db=Java.use("com.tencent.mm.aj.d$b");
    db.aBj.overload().implementation=function(){
        send("aBj Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        var result =  this.aBj()
        return result
    }
    var fb=Java.use("com.tencent.mm.aj.f$b");
    fb.aBj.overload().implementation=function(){
        send("fb aBj Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        var result =  this.aBj()
        return result
    }

    var fb=Java.use("com.tencent.mm.aj.f$b");
    fb.aBj.overload().implementation=function(){
        send("fb aBj Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        var result =  this.aBj()
        return result
    }

    var i=Java.use("com.tencent.mm.aj.i");
    i.convertFrom.overload('android.database.Cursor').implementation=function(arg1){
        send("convertFrom aBj Hook Start...");
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        var result =  this.convertFrom(arg1)
        return result
    }

});
//img_flag reserved1
// intent.putExtra("Contact_User", aVar.getUsername());
// intent.putExtra("Contact_Nick", aVar.getNickName());
// intent.putExtra("Contact_Mobile_MD5", aVar.mo33365JC());
// intent.putExtra("Contact_Alias", aVar.iJY);
// intent.putExtra("Contact_Sex", aVar.iJT);
// intent.putExtra("Contact_Signature", aVar.iJW);
// intent.putExtra("Contact_RegionCode", RegionCodeDecoder.m13147aW(aVar.iKc, aVar.iJU, aVar.iJV));
// intent.putExtra("Contact_Scene", 13);
// intent.putExtra("Contact_ShowUserName", false);