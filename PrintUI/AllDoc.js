var app = new Vue({
    el: '#app',
    data: {
        ready: true,
        documents: [],
        showAllDocs: false
    },
    methods: {
        RetrieveAllDocs: function () {

            axios.get("https://mcsrv.icu/getDocuments")
                .then((res) => {
                    var rst = res.data.result
                    for(var x=0;x<rst.length;x++){
                        rst[x].qr="https://mcsrv.icu/qr?urlEncoded="+btoa("https://mcsrv.icu/viewDocumentByID?docID="+rst[x].docID)
                    }
                    this.documents=rst
                })

        }
    },
    mounted: function () {

        this.RetrieveAllDocs()

    }
})