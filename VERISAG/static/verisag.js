$(document).ready(function() {

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
            $('#output').append("Analysis beginning.  This may up to 15 minutes unless the requested attack graph is cached.");

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
                    $('#output').append("Mitigate " + data.controls +
                     " to eliminiate " + data.removed_paths +
                     "% of attack paths and improve defenses on remaining paths by " + data.dist_increase + "%."
                    );
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    //alert(jqXHR.responseText);
                    alert(errorThrown);
                }
            });
        };
    });

});