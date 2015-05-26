// 
var graphInstance;

var data = {"src1->dst1": .1, "src2->dst2": .2, "src3->dst3": .3};

$(document).ready(function() {
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
            graphInstance = s;
        }
    );

    // Draw a bar chart of all potential paths
    // https://www.bignerdranch.com/blog/create-data-driven-documents-with-d3js/
    // http://bost.ocks.org/mike/bar/2/
    // http://www.jqplot.com/tests/bar-charts.php
    // http://canvasjs.com/editor/?id=http://canvasjs.com/example/gallery/bar/mobile_usage/
    // TODO 
    var data = [{"key": "Initial State",
                "color": "#d67777",
                "values": [
                    {"label": "src1->dst1", "value": 0.10}, 
                    {"label": "src2->dst2", "value": 0.20}, 
                    {"label": "src3->dst3", "value": 0.30}
                ]
                }
                ];  // Test data

//    var options = {
//            title: {
//                text: "Attack Paths"
//            },
//                    animationEnabled: true,
//            data: [
//            {
//                type: "bar", //change it to line, area, bar, pie, etc
//                dataPoints: data
//            }
//            ]
//        };
//
//        $("#chart").CanvasJSChart(options);
    // http://nvd3.org/examples/multiBarHorizontal.html
    nv.addGraph(function() {
        var chart = nv.models.multiBarHorizontalChart()
            .x(function(d) { return d.label })
            .y(function(d) { return d.value })
            .margin({top: 30, right: 20, bottom: 50, left: 175})
            .showValues(true)           //Show bar value next to each bar.
            .tooltips(true)             //Show tooltips on hover.
//            .duration(350)
            .showControls(true);        //Allow user to switch between "Grouped" and "Stacked" mode.

        chart.yAxis
            .tickFormat(d3.format(',.2f'));

        d3.select('#chart1 svg')
            .datum(data)
            .call(chart);

        nv.utils.windowResize(chart.update);

        return chart;
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
                console.log(data)

                // format the data
                var chart_data = [{"key": "Without Mitigation",
                                    "color": "#d67777",
                                    "values": []
                }]; 
                for (var key in data) {
                    chart_data[0].values.push({"label": key, "value": data[key]})
                }

                // Sor tthe data
                chart_data[0].values.sort(function(a, b) {
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

//                for (var i = 0; i < chart_data[0].values.length; i++) {
//                    if (chart_data[0]['values'][i]['value'] == 0) {
//                        chart_data[0]['values'][i].push(chart_data[0]['values'][i].splice)
//                    }
//                }

                // Build the bar chart of paths with the paths
                $('#chart1 svg').empty();
                nv.addGraph(function() {
                    var chart = nv.models.multiBarHorizontalChart()
                        .x(function(d) { return d.label })
                        .y(function(d) { return d.value })
                        .margin({top: 30, right: 20, bottom: 50, left: 175})
                        .showValues(true)           //Show bar value next to each bar.
                        .tooltips(true)             //Show tooltips on hover.
            //            .duration(350)
                        .showControls(true);        //Allow user to switch between "Grouped" and "Stacked" mode.

                    chart.yAxis
                        .tickFormat(d3.format(',.2f'));

                    d3.select('#chart1 svg')
                        .datum(chart_data)
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

        // grey out all non-selected attributes and associated edges
        // TODO

        // Update bar chart of potential attack paths
        // TODO
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

                    // Augment the bar chart of paths with the longer paths
                    // TODO
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    //alert(jqXHR.responseText);
                    alert(errorThrown);
                }
            });
        };
    });

});