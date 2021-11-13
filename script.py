def GetScriptByID(scriptID = ""):
    if scriptID == "demo":
        return '''
        metaread({"key":"storedinfo","to":"stored"})
        alert({"title":"Hello world!", "message":"This is LincolnScript. $(stored) (you'll see what this mean later.)"})
        alert({"title":"Let me introduce my self...", "message":"Well obviously we can do some cool alerts"})
        alert({"title":"This script is event-driven so..."}) {
            Presented {
                alert({"title":"...this dialogue will present as soon as the previous one finishes presenting."}) {
                    Resolved {
                        alert({"title":"...and this one will pop up after the previous one was closed."})
                    }
                }
            }
        }
        async alert({"title":"This script can also do async. We don't have to wait for the previous action to finish.", "message":"For example, we've set the vairable test to hello."})
        var({"test":"hello"})
        alert({"title":"...so we can show the vairable value like this: $(test)"})
        alert({"title":"This script can also persist a vairable on your device. for example, I've stored 'Ah you're back' to key called storedinfo which will be read to the vairable stored. You can see the changes next time."})
        metawrite({"key":"storedinfo","value":"Ah you're back."})
        alert({"title":"This script can also ask you to choose...", "message":"Let's try an option this time"}) {
            Resolved {
                option({"title":"Would you like to be taken to the main screen?", "message":"If you press cancel, you will be taken to the log in screen."}){
                    Continued {
                        present({"storyboard":"App", "identifier":"App.Main"}) {
                            Presented {
                                alert({"title":"That was cool right?"})
                            }
                        }
                    }
                    Cancelled {
                        present({"storyboard":"App", "identifier":"App.Login"}) {
                            Presented {
                                alert({"title":"That was cool right?"})
                            }
                        }
                    }
                }
                alert({"title":"This is presented before the view pops up"})
            }
        }
    '''
    else:
        return None