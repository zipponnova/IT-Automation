angular.module('bakshiApp', [])
  .controller('bakshiCtrl', function($scope, $http) {
    
    // Initialize variables
    $scope.headers = []; // Array to store table headers
    $scope.rows = []; // Array to store table rows
    $scope.filters = {
      serialNumber: '',
      platform: '',
      nameEmail: ''
    }; // Object to store filter values
    
    // Function to handle comparing the CSV files
    $scope.compareCSV = function() {
      console.log('Comparing CSV files...');
      // Make API call to initiate CSV comparison
      $http.get('/compare', { params: $scope.filters })
        .then(function(response) {
          $scope.headers = response.data.headers;
          $scope.rows = response.data.rows;
        })
        .catch(function(error) {
          console.error(error);
        });
    };

    $scope.generateReport = function() {
      // Send POST request to server to generate report
      $http({
        method: 'POST',
        url: '/report',
        data: {
          platform: $scope.filters.platform,
          nameEmail: $scope.filters.nameEmail,
          serialNumber: $scope.filters.serialNumber,
          presence: $scope.filters.presence
        },
        headers: {'Content-Type': 'application/json'}
      }).then(function successCallback(response) {
        console.log('Report generated successfully');
        // Handle success response
      }, function errorCallback(response) {
        console.error('Error generating report:', response.data);
        // Handle error response
      });
    };

