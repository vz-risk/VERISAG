$(document).ready(function() {

    $("#analyze_button").click(function() {
        var o = {
            "worry": $('#worries').val(),
            "attributes": $('#attributes').val()
        };

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
    });

});