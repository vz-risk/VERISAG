// 
var graphInstance;

$(document).ready(function() {
    var all_paths;
    // instantiate the sigma instance so we can reference it
    //var s = new sigma('sigmajs_container');

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
            // Store the original colors for use later
            s.graph.nodes().forEach(function(n) {
            n.originalColor = n.color;
            });
            s.graph.edges().forEach(function(e) {
            e.originalColor = e.color;
            });

            // Store the graph to a global variable
            graphInstance = s;
        }
    );

    // Draw a bar chart of all potential paths
    // http://nvd3.org/examples/multiBarHorizontal.html
    var wo_mitigation = {"key": "Without Mitigation",
                        "color": "#d67777",
                        "values": []
    }; 
    // Get the values from the initial graph
    var o = {
        "worry": "all"
    };
    // request the paths
    $.ajax({
        type: "GET",
        url: "/paths/",
        contentType: "application/json; charset=utf-8",
        data: o,
        traditional:true,
        success: function(data) {
            // Debug
//            console.log(data)

            // format chart data
            all_paths = format_chart_data(data);
            wo_mitigation["values"] = all_paths;

            // Build the bar chart of paths with the paths
            $('#chart1 svg').empty();
            nv.addGraph(function() {
                var chart = nv.models.multiBarHorizontalChart()
                    .x(function(d) { return d.label })
                    .y(function(d) { return d.value })
                    .margin({top: 30, right: 20, bottom: 50, left: 175})
                    .showValues(true)           //Show bar value next to each bar.
                    .tooltips(true)             //Show tooltips on hover.
//                    .duration(350)
                    .showControls(false);        //Allow user to switch between "Grouped" and "Stacked" mode.

                chart.yAxis
                    .tickFormat(d3.format(',.2f'));

                d3.select('#chart1 svg')
                    .datum([wo_mitigation])
                    .call(chart);

                nv.utils.windowResize(chart.update);

                return chart;
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            //alert(jqXHR.responseText);
            alert(errorThrown);
        }
    });


    // When worries is changed
    $("#worries").change(function () {
        // Clear the analysis
        $('#output').empty();
        $('#output').append("Please click the 'analyze' button to analyze the graph.");

        // Update the graph
        $('#sigmajs_container').empty();
        var end = this.value;
//        console.log('./static/' + end + '.gexf');
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
                // Store the original colors for use later
                s.graph.nodes().forEach(function(n) {
                n.originalColor = n.color;
                });
                s.graph.edges().forEach(function(e) {
                e.originalColor = e.color;
                });

                // Store the graph to a global variable
                graphInstance = s;
            }
        );

        // Update bar chart of potential attack paths
        // Set the data to send
        var o = {
            "worry": $('#worries').val()
        };
        // request the paths
        $.ajax({
            type: "GET",
            url: "/paths/",
            contentType: "application/json; charset=utf-8",
            data: o,
            traditional:true,
            success: function(data) {
                // Debug
//                console.log(data);

                // format chart data
                all_paths = format_chart_data(data);
                wo_mitigation["values"] = all_paths;

                // Filter the path by selected attributes
                var selected_attributes = get_attributes($("#attributes").val());
                
                var wo_values_2 = [];
                for (var i = 0; i < all_paths.length; i++) {
                    // get the destination
                    var dst = all_paths[i]['label'].split("->",2);
                    //console.log(dst[1]);
                    // if the destination is in our attribute list, add it to the new values
                    if ($.inArray(dst[1], selected_attributes) != -1) {
                        wo_values_2.push(all_paths[i]);
                    }
                }
                wo_mitigation["values"] = wo_values_2;

                // Build the bar chart of paths with the paths
                $('#chart1 svg').empty();
                nv.addGraph(function() {
                    var chart = nv.models.multiBarHorizontalChart()
                        .x(function(d) { return d.label })
                        .y(function(d) { return d.value })
                        .margin({top: 30, right: 20, bottom: 50, left: 175})
                        .showValues(true)           //Show bar value next to each bar.
                        .tooltips(true)             //Show tooltips on hover.
//                        .duration(350)
                        .showControls(false);        //Allow user to switch between "Grouped" and "Stacked" mode.

                    chart.yAxis
                        .tickFormat(d3.format(',.2f'));

                    d3.select('#chart1 svg')
                        .datum([wo_mitigation])
                        .call(chart);

                    nv.utils.windowResize(chart.update);

                    return chart;
                });
            },
            error: function(jqXHR, textStatus, errorThrown) {
                //alert(jqXHR.responseText);
                alert(errorThrown);
            }
        });
    });


    // When Protect is changed
    $("#attributes").change(function() {
        // Clear the analysis
        $('#output').empty();
        $('#output').append("Please click the 'analyze' button to analyze the graph.");

        // Get the attributes
        var selected_attributes = get_attributes($("#attributes").val());

        //console.log(selected_attributes);

        // Grey out attribute->end edges that aren't selected attributes
        ////////////////////////
        var s = graphInstance;
        var end_node;
        // Get the end attribute.  (There has to be a better way than this)
        s.graph.nodes().forEach(function(n) {
            if (n.label == "end") {
                end_node = n.id
            };
        });
        // Set all nodes to grey
        var nodes_to_grey = [];
        s.graph.nodes().forEach(function(n) {
          if (/^attribute./.test(n.label) & ($.inArray(n.label, selected_attributes) == -1)) {
            nodes_to_grey.push(n.id)
          }
        });
        s.graph.edges().forEach(function(e) {
          if (($.inArray(e.source, nodes_to_grey) != -1) & (e.target == end_node)) {
            e.color = '#eee';
          } else {
            e.color = e.originalColor;
          }
        });
        s.refresh();

        // Update bar chart of potential attack paths
        //////////////////
       var wo_values_2 = [];
        for (var i = 0; i < all_paths.length; i++) {
            // get the destination
            var dst = all_paths[i]['label'].split("->",2);
            //console.log(dst[1]);
            // if the destination is in our attribute list, add it to the new values
            if ($.inArray(dst[1], selected_attributes) != -1) {
                wo_values_2.push(all_paths[i]);
            }
        }
        wo_mitigation["values"] = wo_values_2;

        //console.log(wo_mitigation)

        $('#chart1 svg').empty();
        nv.addGraph(function() {
            var chart = nv.models.multiBarHorizontalChart()
                .x(function(d) { return d.label })
                .y(function(d) { return d.value })
                .margin({top: 30, right: 20, bottom: 50, left: 175})
                .showValues(true)           //Show bar value next to each bar.
                .tooltips(true)             //Show tooltips on hover.
//                        .duration(350)
                .showControls(false);        //Allow user to switch between "Grouped" and "Stacked" mode.

            chart.yAxis
                .tickFormat(d3.format(',.2f'));

            d3.select('#chart1 svg')
                .datum([wo_mitigation])
                .call(chart);

            nv.utils.windowResize(chart.update);

            return chart;
                });
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

                    // DEBUG
//                  console.log(data.path_lengths)

                    // Augment the bar chart of paths with the longer paths
                    // get the mitigated path data
                    var w_mitigation = {"key": "With Mitigation",
                                        "color": "#FF0000",
                                        "values": []
                    };
                    w_mitigation["values"] = format_chart_data(data.path_lengths);

                    // build chart
                    $('#chart1 svg').empty();
                    nv.addGraph(function() {
                        var chart = nv.models.multiBarHorizontalChart()
                            .x(function(d) { return d.label })
                            .y(function(d) { return d.value })
                            .margin({top: 30, right: 20, bottom: 50, left: 175})
                            .showValues(true)           //Show bar value next to each bar.
                            .tooltips(true)             //Show tooltips on hover.
//                            .duration(350)
                            .showControls(false);        //Allow user to switch between "Grouped" and "Stacked" mode.

                        chart.yAxis
                            .tickFormat(d3.format(',.2f'));

                        d3.select('#chart1 svg')
                            .datum([wo_mitigation, w_mitigation])
                            .call(chart);

                        nv.utils.windowResize(chart.update);

                        return chart;
                    });
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    //alert(jqXHR.responseText);
                    alert(errorThrown);
                }

            });
        };
    });


    function get_attributes(attributes) {
        // Take a string from the properties window and return the associated attributes
        var selected_attributes = [];
        for (var i = 0; i < attributes.length; i++) {
            if (attributes[i] == "-") {
                $.noop
            } else if (attributes[i] == "Availability") {
                selected_attributes = selected_attributes.concat([
                    "attribute.availability.variety.Destruction",
                    "attribute.availability.variety.Loss",
                    "attribute.availability.variety.Interruption",
                    "attribute.availability.variety.Degradation",
                    "attribute.availability.variety.Acceleration",
                    "attribute.availability.variety.Obscuration",
                    "attribute.availability.variety.Other"
                ]);
            } else if (attributes[i] == "Confidentiality") {
                selected_attributes = selected_attributes.concat([
                    "attribute.confidentiality.data.variety.Credentials",
                    "attribute.confidentiality.data.variety.Bank",
                    "attribute.confidentiality.data.variety.Classified",
                    "attribute.confidentiality.data.variety.Copyrighted",
                    "attribute.confidentiality.data.variety.Digital certificate",
                    "attribute.confidentiality.data.variety.Medical",
                    "attribute.confidentiality.data.variety.Payment",
                    "attribute.confidentiality.data.variety.Personal",
                    "attribute.confidentiality.data.variety.Internal",
                    "attribute.confidentiality.data.variety.Source code",
                    "attribute.confidentiality.data.variety.System",
                    "attribute.confidentiality.data.variety.Secrets",
                    "attribute.confidentiality.data.variety.Virtual currency",
                    "attribute.confidentiality.data.variety.Other"
                ]);
            } else if (attributes[i] == "Integrity") {
                selected_attributes = selected_attributes.concat([
                    "attribute.integrity.variety.Created account",
                    "attribute.integrity.variety.Defacement",
                    "attribute.integrity.variety.Hardware tampering",
                    "attribute.integrity.variety.Alter behavior",
                    "attribute.integrity.variety.Fraudulent transaction",
                    "attribute.integrity.variety.Log tampering",
                    "attribute.integrity.variety.Repurpose",
                    "attribute.integrity.variety.Misrepresentation",
                    "attribute.integrity.variety.Modify configuration",
                    "attribute.integrity.variety.Modify privileges",
                    "attribute.integrity.variety.Modify data",
                    "attribute.integrity.variety.Software installation",
                    "attribute.integrity.variety.Other"
                ]);
            } else {
                selected_attributes = selected_attributes.concat([attributes[i]]);
            }
        };
        return selected_attributes;
    };


    function format_chart_data(data) {
        // Takes data from the /paths/ API and formats it for the 'values' section of nld3

        var return_data = [];

        // format API returned data to that needed by the charting function
        for (var key in data) {
            return_data.push({"label": key, "value": data[key]})
        }

        // Sor tthe data
        return_data.sort(function(a, b) {
            a = a["value"];
            b = b["value"];

            if ( a == 0 & b != 0) {
                return 1;
            } else if (b == 0 & a != 0) {
                return -1;
            } else {
                return a < b ? -1 : (a > b ? 1: 0)
            }
        })

        // Return the data
        return return_data
    }
});