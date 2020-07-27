var app = new Vue({
    el: '#app',
    data: {
        ready: true,
        documents: [],
        showAllDocs: false
    },
    methods: {
        RetrieveAllDocs: function () {

            axios.get("https://apis.mcsrv.icu/getDocuments")
                .then((res) => {
                    var rst = res.data.result
                    for(var x=0;x<rst.length;x++){
                        rst[x].qr="https://apis.mcsrv.icu/qr?urlEncoded="+btoa("https://apis.mcsrv.icu/viewDocumentByID?docID="+rst[x].docID)
                        rst[x].dScanned = new Date(rst[x].dScanned*1000)
                        rst[x].link = "https://apis.mcsrv.icu/viewDocumentByID?docID="+rst[x].docID
                    }
                    this.documents=rst
                })

        }
    },
    mounted: function () {

        this.RetrieveAllDocs()

    }
})