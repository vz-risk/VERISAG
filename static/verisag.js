$(document).ready(function() {
    sigma.parsers.gexf(
        './static/all.gexf',
        {   // Here is the ID of the DOM element that
            // will contain the graph:
            container: 'sigmajs_container'
        },
        function(s) {
            // This function will be executed when the
            // graph is displayed, with "s" the related
            // sigma instance.
        }
    );

    $("#worries").change(function () {
        $('#sigmajs_container').empty();
        var end = this.value;
        console.log('./static/' + end + '.gexf');
        sigma.parsers.gexf(
            './static/' + end + '.gexf',
            {   // Here is the ID of the DOM element that
                // will contain the graph:
                container: 'sigmajs_container'
            },
            function(s) {
                // This function will be executed when the
                // graph is displayed, with "s" the related
                // sigma instance.
            }
        );
    });


    $("#analyze_button").click(function() {
        // DBUG
        //alert($('#attributes').val())
        var o = {
            "worry": $('#worries').val(),
            "attributes": $('#attributes').val()
        };

        // if an unacceptable worry is indicated, remove it
        if (o['worry'] ==  "-") {
            alert("The 'worry' choise is invalid.  please select 'everything' or a valid worry.")
        } else {
            // TODO: Need to parse through $('#attributes').val() to get a string of comma-separated attributes 

            $('#output').empty();
            $('#output').append("Analysis beginning.  This may take a few seconds up to 15 minutes if the requested attack graph is not cached.");

            $.ajax({
                type: "GET",
                url: "/analyze/",
                contentType: "application/json; charset=utf-8",
                data: o,
                traditional:true,
                success: function(data) {
                    // Debug
                    //alert(data.controls + data.removed_paths + data.dist_increase)
                    // TODO: create a string out of the controls?
                    var controls = "";
                    $('#output').empty();
                    if (data.error != "") {
                        $('#output').append("Error: " + data.error)
                    } else {
                        $('#output').append("Mitigate " + data.controls +
                         " to eliminiate " + data.removed_paths +
                         "% of attack paths and improve defenses on remaining paths by " + data.dist_increase + "%."
                        );
                    };
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    //alert(jqXHR.responseText);
                    alert(errorThrown);
                }
            });
        };
    });

});