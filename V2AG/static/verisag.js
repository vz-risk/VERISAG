$(document).ready(function() {

    $("#analyze_button").click(function() {
        var o = {
            "worry": $('#worries').val(),
            "attributes": $('#attributes').val()
        };

        // if an unacceptable worry is indicated, remove it
        if (o['worry'] ==  "-") {
            alert("The 'worry' choise is invalid.  please select 'everything' or a valid worry.")
        } else {
            // TODO: Need to parse through $('#attributes').val() to get a string of comma-separated attributes 


            $.ajax({
                type: "GET",
                url: "/analyze",
                contentType: "application/json; charset=utf-8",
                data: o,
                success: function(data) {
                    // TODO: create a string out of the controls?
                    var controls = "";
                   $('.output').append("Apply" + data.controls +
                    "control(s) to eliminiate " + data.removed_paths +
                    "% of attack paths and improve defenses on remaining paths by " + data.dist_increase + "%."
                    );
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert(errorThrown);
                }
            });
        };
    });

});